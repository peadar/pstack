PSTACK(1)                 BSD General Commands Manual                PSTACK(1)

NNAAMMEE
     ppssttaacckk — print stack traces of threads in a running process or a core
     file

SSYYNNOOPPSSIISS
     ppssttaacckk [--aa] [--jj] [--nn] [--pp] [--ss] [--tt] [--vv] [--bb _s_e_c_o_n_d_s] [--gg _d_i_r_e_c_t_o_r_y]
            ⟨_e_x_e_c_u_t_a_b_l_e | _p_i_d | _c_o_r_e⟩ *
     ppssttaacckk --dd _e_l_f_-_f_i_l_e
     ppssttaacckk --DD _e_l_f_-_f_i_l_e
     ppssttaacckk --VV
     ppssttaacckk --hh

DDEESSCCRRIIPPTTIIOONN
     Displays the stack traces of each thread in the running process with
     process id _p_i_d or from the core file _c_o_r_e

     Normal invocation prints the stack trace from a core file or running
     process. This implementation understands the stack unwinding data in
     eh_frame sections, and properly unwinds through stack frames of code com‐
     piled with _-_f_o_m_i_t_-_f_r_a_m_e_-_p_o_i_n_t_e_r and on x86_64

     Arguments are as follows.

     --aa          Show values of arguments passed to functions if possible
                 (requires DWARF debug data for function's code). This also
                 works in python mode.

     --jj          Use JSON format for the stack output

     --nn          Do not attempt to find external debug information. DWARF
                 debug information and symbol tables may be contained in sepa‐
                 rate ELF objects, as referenced by either the .gnu_debuglink
                 or inferred by the GNU "build ID" ELF note.

     --pp          Attempt to print the stack trace from any discovered python
                 interpreters and threads. This feature is experimental, and
                 only works with Python 2.7.

     --ss          Do not attempt to locate source code information (file and
                 line number) for each frame. Finding the source locations may
                 slow down stack tracing.

     --tt          Do not use the thread_db library to associate userland thread
                 data structures with kernel level LWPs. For modern linux sys‐
                 tems, LWPs and user mode threads are effectively the same
                 thing. At this point the only benefit of using this library
                 is to associated pthread IDs with the LWPs.

     --vv          Produce more verbose diagnostics. Can be repeated to increase
                 verbosity further.

     --bb _N        Poll-mode: repeatedly trace stacks every _N seconds, until
                 interrupted.

     --gg _d_i_r_e_c_t_o_r_y
                 Use _d_i_r_e_c_t_o_r_y as a potential location to find debug ELF
                 images, as referred to by a build-id note or gnu_debuglink
                 section. The default directory is _/_u_s_r_/_l_i_b_/_d_e_b_u_g

     ⟨_e_x_e_c_u_t_a_b_l_e | _c_o_r_e | _p_i_d⟩
                 List of core files or PIDs to trace. An executable image
                 specified on the command line will override the executable
                 derived from the core or processes specified after it until a
                 different executable image is provided

     There are some options to aid debugging issues with ELF and DWARF bina‐
     ries. Namely

     ppssttaacckk --DD _E_L_F_-_i_m_a_g_e
                 Format DWARF debugging information of the provided _E_L_F_-_i_m_a_g_e
                 in JSON

     ppssttaacckk --dd _E_L_F_-_i_m_a_g_e
                 Format ELF information of the provided _E_L_F_-_i_m_a_g_e in JSON

     ppssttaacckk --VV   Print git commit-id used to build ppssttaacckk

     ppssttaacckk --hh   Print usage synopsis ppssttaacckk

SSEEEE AALLSSOO
     procfs(5) ptrace(2)

TTOODDOO
     ··   Support rela for object files

     ··   This actually works on ARM (i.e., raspi), but needs debug_frame.
         Apparently, ARM has its own magical sections for storing unwind
         information that it might be worth implementing.

     ··   Support inlined subroutines, so we show the surrounding scopes as
         part
           of the stack trace.
     works on x86_64 and i686 only.

AAUUTTHHOORRSS
     Peter Edwards <peadar (at) isainmdom dot net>

BSD                              Mar 29, 2018                              BSD
