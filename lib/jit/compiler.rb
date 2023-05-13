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

    # Compile a method. Called after --rjit-call-threshold calls.
    def compile(iseq)
      # Write machine code to this assembler.
      asm = Assembler.new

      # Iterate over each YARV instruction.
      insn_index = 0
      stack_size = 0

      while insn_index < iseq.body.iseq_size
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
          operand = iseq.body.iseq_encoded[insn_index + 1]
          asm.test(STACK[stack_size], C.to_value(false))
          asm.jne(operand)
          asm.test(STACK[stack_size], C.to_value(nil))
          asm.jne(operand)
        in :putself
          asm.mov(STACK[stack_size], [CFP, C.rb_control_frame_t.offsetof(:self)])
          stack_size += 1
        end
        insn_index += insn.len
      end

      # Write machine code into memory and use it as a JIT function.
      iseq.body.jit_func = write(asm)
    rescue Exception => e
      abort e.full_message
    end

    private

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
  end
end
