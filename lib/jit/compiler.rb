require_relative 'assembler'

module JIT
  class Compiler
    # Utilities to call C functions and interact with the Ruby VM.
    # See: https://github.com/ruby/ruby/blob/master/rjit_c.rb
    C = RubyVM::RJIT::C

    # Metadata for each YARV instruction.
    INSNS = RubyVM::RJIT::INSNS

    # Size of the JIT buffer
    JIT_BUF_SIZE = 1024 * 1024

    # Initialize a JIT buffer. Called only once.
    def initialize
      # Allocate 64MiB of memory. This returns the memory address.
      @jit_buf = C.mmap(JIT_BUF_SIZE)
      # The number of bytes that have been written to @jit_buf.
      @jit_pos = 0
    end

    STACK = [:r8, :r9, :r10, :r11]
    EC = :rdi
    CFP = :rsi

    Branch = Struct.new(:start_addr, :compile)

    # Compile a method. Called after --rjit-call-threshold calls.
    def compile(iseq)

      blocks = split_blocks(iseq)

      branches = []

      blocks.each.with_index do |block, block_index|
        block[:start_addr] = compile_block(iseq, block, blocks, branches)
        iseq.body.jit_func = block[:start_addr] if block_index == 0
      end

      branches.each do |branch|
        with_addr(branch[:start_addr]) do
          asm = Assembler.new
          branch.compile.call(asm)
          write(asm)
        end
      end

      # Write machine code into memory and use it as a JIT function.
    rescue Exception => e
      abort e.full_message
    end

    private

    def compile_block(iseq, block, blocks, branches)
      # Write machine code to this assembler.
      asm = Assembler.new
      # Iterate over each YARV instruction.
      insn_index = block[:start_index]
      stack_size = block[:stack_size]

      while insn_index <= block[:end_index]
        insn = INSNS.fetch(C.rb_vm_insn_decode(iseq.body.iseq_encoded[insn_index]))
        case insn.name
        in :nop
          # none
        in :putnil
          asm.mov(STACK[stack_size], C.to_value(nil))
          stack_size += 1
        in :leave
          asm.add(CFP, C.rb_control_frame_t.size)
          asm.mov([EC, C.rb_execution_context_t.offsetof(:cfp)], CFP)
          asm.mov(:rax, STACK[stack_size - 1])
          asm.ret
        in :putobject_INT2FIX_0_
          asm.mov(STACK[stack_size], C.to_value(0))
          stack_size += 1
        in :putobject_INT2FIX_1_
          asm.mov(STACK[stack_size], C.to_value(1))
          stack_size += 1
        in :putobject
          # takes 1 arugment. Is it always so?
          operand = iseq.body.iseq_encoded[insn_index + 1]
          asm.mov(STACK[stack_size], operand)
          stack_size += 1
        in :opt_plus
          rhs = STACK[stack_size - 1]
          lhs = STACK[stack_size - 2]
          stack_size -= 1
          asm.add(lhs, rhs)
          asm.add(lhs, -1)
        in :opt_minus
          rhs = STACK[stack_size - 1]
          lhs = STACK[stack_size - 2]
          stack_size -= 1
          asm.sub(lhs, rhs)
          asm.add(lhs, 1)
        in :getlocal_WC_0
          operand = iseq.body.iseq_encoded[insn_index + 1]
          asm.mov(:rax, [CFP, C.rb_control_frame_t.offsetof(:ep)])
          asm.mov(STACK[stack_size], [:rax, -C.VALUE.size * operand])
          stack_size += 1
        in :opt_lt
          rhs = STACK[stack_size - 1]
          lhs = STACK[stack_size - 2]
          stack_size -= 1

          asm.cmp(lhs, rhs)
          asm.mov(lhs, C.to_value(false))
          asm.mov(:rax, C.to_value(true))
          asm.cmovl(lhs, :rax)
        in :branchunless
          next_index = insn_index + insn.len
          next_block = blocks.find { |b| b[:start_index] == next_index }

          jump_index = next_index + iseq.body.iseq_encoded[insn_index + 1]
          jump_block = blocks.find { |b| b[:start_index] == jump_index }

          asm.test(STACK[stack_size - 1], ~C.to_value(nil))

          branch = Branch.new
          branch.compile = proc do |asm|
            puts "branch.compile is called"
            dummy_addr = @jit_buf + JIT_BUF_SIZE
            asm.jz(jump_block.fetch(:start_addr, dummy_addr))
            asm.jmp(next_block.fetch(:start_addr, dummy_addr))
          end
          asm.branch(branch) {
            branch.compile.call(asm)
          } # TODO: why yield?

          branches << branch
        in :putself
          asm.mov(STACK[stack_size], [CFP, C.rb_control_frame_t.offsetof(:self)])
          stack_size += 1
        in :opt_send_without_block
          cd = C.rb_call_data.new(iseq.body.iseq_encoded[insn_index + 1])
          callee_iseq = cd.cc.cme_.def.body.iseq.iseqptr
          if callee_iseq.body.jit_func == 0 # NULL
            compile(callee_iseq)
          end

          # | locals | cme | block_handler | frame type (callee EP) | stack bottom (callee SP) |

          # rax is now sp
          asm.mov(:rax, [CFP, C.rb_control_frame_t.offsetof(:sp)])
          argc = C.vm_ci_argc(cd.ci)

          # The arguments are on the stack. Push them to the sp.
          argc.times do |i|
            asm.mov([:rax, i * C.VALUE.size], STACK[stack_size - argc + i])
          end

          asm.sub(CFP, C.rb_control_frame_t.size)
          asm.mov([EC, C.rb_execution_context_t.offsetof(:cfp)], CFP)
          # Set SP
          asm.add(:rax, C.VALUE.size * (argc + 3))
          asm.mov([CFP, C.rb_control_frame_t.offsetof(:sp)], :rax)
          # Set EP
          asm.sub(:rax, C.VALUE.size)
          asm.mov([CFP, C.rb_control_frame_t.offsetof(:ep)], :rax)
          # Receiver
          asm.sub(:rax, STACK[stack_size - argc - 1])
          asm.mov([CFP, C.rb_control_frame_t.offsetof(:self)], :rax)

          STACK.each { |e| asm.push(e) }

          # Call the JIT func
          asm.call(callee_iseq.body.jit_func)

          STACK.reverse_each { |reg| asm.pop(reg) }

          # Set a return value
          asm.mov(STACK[stack_size - C.vm_ci_argc(cd.ci) - 1], :rax)

          stack_size -= C.vm_ci_argc(cd.ci)
        end
        insn_index += insn.len
      end

      write(asm)
    end

    # Write bytes in a given assembler into @jit_buf.
    # @param asm [JIT::Assembler]
    def write(asm)
      jit_addr = @jit_buf + @jit_pos

      # Append machine code to the JIT buffer
      C.mprotect_write(@jit_buf, JIT_BUF_SIZE) # make @jit_buf writable
      @jit_pos += asm.assemble(jit_addr)
      C.mprotect_exec(@jit_buf, JIT_BUF_SIZE) # make @jit_buf executable

      # Dump disassembly if --rjit-dump-disasm
      if C.rjit_opts.dump_disasm
        C.dump_disasm(jit_addr, @jit_buf + @jit_pos).each do |address, mnemonic, op_str|
          puts "  0x#{format("%x", address)}: #{mnemonic} #{op_str}"
        end
        puts
      end

      jit_addr
    end

    def split_blocks(iseq, insn_index: 0, stack_size: 0, split_indexes: [])
      return [] if split_indexes.include?(insn_index)

      split_indexes << insn_index

      block = { start_index: insn_index, end_index: nil, stack_size: }
      blocks = [block]

      while insn_index < iseq.body.iseq_size
        insn = INSNS.fetch(C.rb_vm_insn_decode(iseq.body.iseq_encoded[insn_index]))
        case insn.name
        when :branchunless
          block[:end_index] = insn_index
          stack_size += sp_inc(iseq, insn_index)
          next_index = insn_index + insn.len
          blocks += split_blocks(iseq, insn_index: next_index, stack_size:, split_indexes:)
          blocks += split_blocks(iseq, insn_index: next_index + iseq.body.iseq_encoded[insn_index + 1], stack_size:, split_indexes:)
          break
        when :leave
          block[:end_index] = insn_index
          break
        else
          stack_size += sp_inc(iseq, insn_index)
          insn_index += insn.len
        end
      end

      blocks
    end

    def sp_inc(iseq, insn_index)
      insn = INSNS.fetch(C.rb_vm_insn_decode(iseq.body.iseq_encoded[insn_index]))
      case insn.name
      in :opt_plus | :opt_minus | :opt_lt | :leave | :branchunless
        -1
      in :nop
        0
      in :putnil | :putobject_INT2FIX_0_ | :putobject_INT2FIX_1_ | :putobject | :putself | :getlocal_WC_0
        1
      in :opt_send_without_block
        cd = C.rb_call_data.new(iseq.body.iseq_encoded[insn_index + 1])
        -C.vm_ci_argc(cd.ci)
      end
    end

    def with_addr(addr)
      jit_pos = @jit_pos
      @jit_pos = addr - @jit_buf
      yield
    ensure
      @jit_pos = jit_pos
    end
  end
end
