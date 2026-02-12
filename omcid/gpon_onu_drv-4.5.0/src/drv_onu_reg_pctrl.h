/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_pctrl_h
#define _drv_onu_reg_pctrl_h

/** \addtogroup PCTRL_REGISTER
   @{
*/
/* access macros */
#define pctrl_r32(reg) reg_r32(&pctrl->reg)
#define pctrl_w32(val, reg) reg_w32(val, &pctrl->reg)
#define pctrl_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &pctrl->reg)
#define pctrl_r32_table(reg, idx) reg_r32_table(pctrl->reg, idx)
#define pctrl_w32_table(val, reg, idx) reg_w32_table(val, pctrl->reg, idx)
#define pctrl_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, pctrl->reg, idx)
#define pctrl_adr_table(reg, idx) adr_table(pctrl->reg, idx)


/** PCTRL register structure */
struct onu_reg_pctrl
{
   /** Thread Control Register
       Via this register all Virtual Machines in the PCTRL unit can be enabled or disabled individually. When a VM is disabled all threads running on this VM will stop execution. When the VM is enabled again, the program execution resumes at the stopped instruction. */
   unsigned int tctrl0; /* 0x00000000 */
   /** Reserved */
   unsigned int res_0[3]; /* 0x00000004 */
   /** Thread Status Register
       This register indicates wether a Virtual Machine is running or idle. A VM is in idle mode, when the SLEEP instruction is executed. Usually the sleep instruction is only executed in the idle thread of this VM. Therefor the corresponding bit indicates, that the VM is executing the idle thread. Any internal event can wake-up the VM from idle state. */
   unsigned int tstat0; /* 0x00000010 */
   /** Reserved */
   unsigned int res_1[3]; /* 0x00000014 */
   /** Thread Single Step Register
       This register is used to single step the current thread one ore more Virtual Machines simultaniously. Single stepping is only allowed, if the corresponding VM is in disabled state.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int tstep0; /* 0x00000020 */
   /** Reserved */
   unsigned int res_2[3]; /* 0x00000024 */
   /** Thread Debug Mode Register
       This register can be used to switch a thread from regular mode to debug mode. In debug mode the thread is ignoring the PC for program memory access and accesses always the address 0. Together with the single step function a debugger can prepare the instruction at address 0 with an instruction which dumps the internal state to a port or updates the internal state from a port.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int tdebug0; /* 0x00000030 */
   /** Reserved */
   unsigned int res_3[3]; /* 0x00000034 */
   /** Breakpoint Control Register
       This register controls if a Virtual Machine stops when the current thread of this VM has hit a breakpoint. When set, the current thread of the VM will stop execution when a BREAK instruction is executed. When cleared a BREAK instruction for this thread will be ignored.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int bctrl0; /* 0x00000040 */
   /** Reserved */
   unsigned int res_4[3]; /* 0x00000044 */
   /** Breakpoint Status Register
       This register indicates if the current thread of an Virtual Machine has hit a breakpoint. If a breakpoint has been hit, the corresponding bit is set and the thread loops endlessly at this instruction causing the breakpoint until the VM is disabled.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int bstat0; /* 0x00000050 */
   /** Reserved */
   unsigned int res_5[3]; /* 0x00000054 */
   /** Breakpoint Disable Register
       This register can be used to disable one or more Virtual Machines automatically when any breakpoint is hit. This is done by setting the corresponding bit in the TSTOP register. The corresponding BCTRL bit has to be set and a BREAK instruction has to be executed in order to trigger a breakpoint (see BCTRL). Breakpoints can cause an CPU interrupt when the corresponding bit in the ICTRL register is set. The feature can be used to freeze the whole system or only a part of the system upon simultaniously upon a breakpoint event.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int bdis0; /* 0x00000060 */
   /** Reserved */
   unsigned int res_6[3]; /* 0x00000064 */
   /** Interrupt Control Register 0
       This register enables the CPU interrupt for the corresponding bit in the ISTAT register. *** INFO: The registers ICTRL1-3 are shadowed registers. The programed value takes in effect only when writing to ICTRL0. *** */
   unsigned int ictrl0; /* 0x00000070 */
   /** Interrupt Control Register 1
       This register enables the CPU interrupt for the corresponding bit in the ISTAT register. *** INFO: The registers ICTRL1-3 are shadowed registers. The programed value takes in effect only when writing to ICTRL0. *** */
   unsigned int ictrl1; /* 0x00000074 */
   /** Interrupt Control Register 2
       This register enables the CPU interrupt for the corresponding bit in the ISTAT register. *** INFO: The registers ICTRL1-3 are shadowed registers. The programed value takes in effect only when writing to ICTRL0. *** */
   unsigned int ictrl2; /* 0x00000078 */
   /** Interrupt Control Register 3
       This register enables the CPU interrupt for the corresponding bit in the ISTAT register. *** INFO: The registers ICTRL1-3 are shadowed registers. The programed value takes in effect only when writing to ICTRL0. *** */
   unsigned int ictrl3; /* 0x0000007C */
   /** Interrupt Status Register 0
       This registers represents the signal state of all PCTRL signals. Every thread can trigger on of the signals which cause the corresponding bit in ISTAT register to be set. The bits can be acknowledged by the CPU when they are written with a logical one. Every of this signal events serves also as an input to the corresponding thread, thus event i is connect to the interrupt input 0 of theat i. The CPU is the only unit which can observe all interrupts. */
   unsigned int istat0; /* 0x00000080 */
   /** Interrupt Status Register 1
       This registers represents the signal state of all PCTRL signals. Every thread can trigger on of the signals which cause the corresponding bit in ISTAT register to be set. The bits can be acknowledged by the CPU when they are written with a logical one. Every of this signal events serves also as an input to the corresponding thread, thus event i is connect to the interrupt input 0 of theat i. The CPU is the only unit which can observe all interrupts. */
   unsigned int istat1; /* 0x00000084 */
   /** Interrupt Status Register 2
       This registers represents the signal state of all PCTRL signals. Every thread can trigger on of the signals which cause the corresponding bit in ISTAT register to be set. The bits can be acknowledged by the CPU when they are written with a logical one. Every of this signal events serves also as an input to the corresponding thread, thus event i is connect to the interrupt input 0 of theat i. The CPU is the only unit which can observe all interrupts. */
   unsigned int istat2; /* 0x00000088 */
   /** Interrupt Status Register 3
       This registers represents the signal state of all PCTRL signals. Every thread can trigger on of the signals which cause the corresponding bit in ISTAT register to be set. The bits can be acknowledged by the CPU when they are written with a logical one. Every of this signal events serves also as an input to the corresponding thread, thus event i is connect to the interrupt input 0 of theat i. The CPU is the only unit which can observe all interrupts. */
   unsigned int istat3; /* 0x0000008C */
   /** Interrupt Signal Register 0
       This registers can be used to issue one of the PCTRL global signals. Please note, that all ISIG registers, other than ISIG0 are shadow registers only. Signals are only sent, when ISIG0 is written. *** INFO: The registers ISIG1-3 are shadowed registers. The programed value takes in effect only when writing to ISIG0. *** */
   unsigned int isig0; /* 0x00000090 */
   /** Interrupt Signal Register 1
       This registers can be used to issue one of the PCTRL global signals. Please note, that all ISIG registers, other than ISIG0 are shadow registers only. Signals are only sent, when ISIG0 is written. *** INFO: The registers ISIG1-3 are shadowed registers. The programed value takes in effect only when writing to ISIG0. *** */
   unsigned int isig1; /* 0x00000094 */
   /** Interrupt Signal Register 2
       This registers can be used to issue one of the PCTRL global signals. Please note, that all ISIG registers, other than ISIG0 are shadow registers only. Signals are only sent, when ISIG0 is written. *** INFO: The registers ISIG1-3 are shadowed registers. The programed value takes in effect only when writing to ISIG0. *** */
   unsigned int isig2; /* 0x00000098 */
   /** Interrupt Signal Register 3
       This registers can be used to issue one of the PCTRL global signals. Please note, that all ISIG registers, other than ISIG0 are shadow registers only. Signals are only sent, when ISIG0 is written. *** INFO: The registers ISIG1-3 are shadowed registers. The programed value takes in effect only when writing to ISIG0. *** */
   unsigned int isig3; /* 0x0000009C */
   /** Timer Control Register
       This register provides control. */
   unsigned int tictrl; /* 0x000000A0 */
   /** Timer Compare Register
       This register provides the compare value for the timer. */
   unsigned int ticmp; /* 0x000000A4 */
   /** Timer Data Register
       Read and write the current timer value to the timer. */
   unsigned int tidata; /* 0x000000A8 */
   /** Reserved */
   unsigned int res_7; /* 0x000000AC */
   /** Timer Interrupt Destination Register 0
       Configure which signal to be asserted when timer reaches compare value. *** INFO: The registers TIDMASK1-3 are shadowed registers. The programed value takes in effect only when writing to TIDMASK0. *** */
   unsigned int tidmask0; /* 0x000000B0 */
   /** Timer Interrupt Destination Register 1
       Configure which signal to be asserted when timer reaches compare value. *** INFO: The registers TIDMASK1-3 are shadowed registers. The programed value takes in effect only when writing to TIDMASK0. *** */
   unsigned int tidmask1; /* 0x000000B4 */
   /** Timer Interrupt Destination Register 2
       Configure which signal to be asserted when timer reaches compare value. *** INFO: The registers TIDMASK1-3 are shadowed registers. The programed value takes in effect only when writing to TIDMASK0. *** */
   unsigned int tidmask2; /* 0x000000B8 */
   /** Timer Interrupt Destination Register 3
       Configure which signal to be asserted when timer reaches compare value. *** INFO: The registers TIDMASK1-3 are shadowed registers. The programed value takes in effect only when writing to TIDMASK0. *** */
   unsigned int tidmask3; /* 0x000000BC */
   /** Thread Error Register
       This register provides error information when an error is asserted by on of the Virtual Machines. The bits are set when the error occures and can be reset when written with a logical one. */
   unsigned int terr; /* 0x000000C0 */
   /** Reserved */
   unsigned int res_8[3]; /* 0x000000C4 */
   /** Thread Error Interrupt Enable Register
       This register provides the interrupt mask (IRQ-mask) for events found in the TERR regsister. */
   unsigned int terrmask; /* 0x000000D0 */
   /** Reserved */
   unsigned int res_9[3]; /* 0x000000D4 */
   /** TSE Status Register
       This register indicates, if a TSE is currently active.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int tsestat; /* 0x000000E0 */
   /** Reserved */
   unsigned int res_10[3]; /* 0x000000E4 */
   /** TSE Single Step Register
       This register provides single step control for TSE coprocessor elements. When the debug mode in one of the TSEs is activated, commands are executed in a single step. Every time the corresponding bit in the register is wirtten with a one (1), the coprocessor advances one instruction in the microcode RAM and sends the internal state to a predefined destination address (usually the LINK2 interface).NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int tsestep; /* 0x000000F0 */
   /** Reserved */
   unsigned int res_11[3]; /* 0x000000F4 */
   /** Auxilliary Enable Register
       This register enables auxilliary signal inputs of the PCTRL. The PCTRL module has two reserved signal inputs which are conected to an external source in the integrating system. This register controls, if the aux sources are connected to the dedicated AUX0/LTIMER and AUX1/LTIMER signals. When the signals are disabled, these signals are the preferred signals for the global timer events (see TIDMASK), but can also be used as general purpose global signalling lines by the CPU. */
   unsigned int auxen; /* 0x00000100 */
   /** Link Reset Register
       This register provides reset control to linkport networks. */
   unsigned int linkrst; /* 0x00000104 */
   /** Thread Single Step Count Register
       This register defines the number of steps performed when single stepping is used.NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int tstepcnt; /* 0x00000108 */
   /** Reserved */
   unsigned int res_12; /* 0x0000010C */
   /** Thread Stop Register
       Via this register all Virtual Machines in the PCTRL unit can be stopped individually. When a VM is stopped all threads running on this VM will stop execution regardless of the programming in the TCTRL register. When the VM stop is removed, the program execution resumes at the stopped instruction when the VM is enabled in the TCTRL register. NOTE: This register must only be accessed by the debugger kernel. */
   unsigned int tstop0; /* 0x00000110 */
   /** Reserved */
   unsigned int res_13[3]; /* 0x00000114 */
   /** MBIST Control Register
       This register controls the Program RAM BIST of the all PEs.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mctrl; /* 0x00000120 */
   /** MBIST Status Register 0
       This register holds the RAM test signature for PE 0.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mstat0; /* 0x00000124 */
   /** MBIST Status Register 1
       This register holds the RAM test signature for PE 1.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mstat1; /* 0x00000128 */
   /** MBIST Status Register 2
       This register holds the RAM test signature for PE 2.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mstat2; /* 0x0000012C */
   /** MBIST Status Register 3
       This register holds the RAM test signature for PE 3.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mstat3; /* 0x00000130 */
   /** MBIST Status Register 4
       This register holds the RAM test signature for PE 4.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mstat4; /* 0x00000134 */
   /** MBIST Status Register 5
       This register holds the RAM test signature for PE 5.NOTE: This register must only be accessed by the testing kernel. */
   unsigned int mstat5; /* 0x00000138 */
   /** Reserved */
   unsigned int res_14[49]; /* 0x0000013C */
};


/* Fields of "Thread Control Register" */
/** Control for Processing Element 5, Virtual Machine 2
    This bit controls Virtual Machine 5.2 and the corresponding ThreadsThread 5.2.0Thread 5.2.1Thread 5.2.2Thread 5.2.3 */
#define PCTRL_TCTRL0_EN52 0x00400000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN52_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN52_EN 0x00400000
/** Control for Processing Element 5, Virtual Machine 1
    This bit controls Virtual Machine 5.1 and the corresponding ThreadsThread 5.1.0Thread 5.1.1Thread 5.1.2Thread 5.1.3 */
#define PCTRL_TCTRL0_EN51 0x00200000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN51_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN51_EN 0x00200000
/** Control for Processing Element 5, Virtual Machine 0
    This bit controls Virtual Machine 5.0 and the corresponding ThreadsThread 5.0.0Thread 5.0.1Thread 5.0.2Thread 5.0.3 */
#define PCTRL_TCTRL0_EN50 0x00100000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN50_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN50_EN 0x00100000
/** Control for Processing Element 4, Virtual Machine 2
    This bit controls Virtual Machine 4.2 and the corresponding ThreadsThread 4.2.0Thread 4.2.1Thread 4.2.2Thread 4.2.3 */
#define PCTRL_TCTRL0_EN42 0x00040000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN42_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN42_EN 0x00040000
/** Control for Processing Element 4, Virtual Machine 1
    This bit controls Virtual Machine 4.1 and the corresponding ThreadsThread 4.1.0Thread 4.1.1Thread 4.1.2Thread 4.1.3 */
#define PCTRL_TCTRL0_EN41 0x00020000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN41_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN41_EN 0x00020000
/** Control for Processing Element 4, Virtual Machine 0
    This bit controls Virtual Machine 4.0 and the corresponding ThreadsThread 4.0.0Thread 4.0.1Thread 4.0.2Thread 4.0.3 */
#define PCTRL_TCTRL0_EN40 0x00010000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN40_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN40_EN 0x00010000
/** Control for Processing Element 3, Virtual Machine 2
    This bit controls Virtual Machine 3.2 and the corresponding ThreadsThread 3.2.0Thread 3.2.1Thread 3.2.2Thread 3.2.3 */
#define PCTRL_TCTRL0_EN32 0x00004000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN32_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN32_EN 0x00004000
/** Control for Processing Element 3, Virtual Machine 1
    This bit controls Virtual Machine 3.1 and the corresponding ThreadsThread 3.1.0Thread 3.1.1Thread 3.1.2Thread 3.1.3 */
#define PCTRL_TCTRL0_EN31 0x00002000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN31_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN31_EN 0x00002000
/** Control for Processing Element 3, Virtual Machine 0
    This bit controls Virtual Machine 3.0 and the corresponding ThreadsThread 3.0.0Thread 3.0.1Thread 3.0.2Thread 3.0.3 */
#define PCTRL_TCTRL0_EN30 0x00001000
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN30_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN30_EN 0x00001000
/** Control for Processing Element 2, Virtual Machine 2
    This bit controls Virtual Machine 2.2 and the corresponding ThreadsThread 2.2.0Thread 2.2.1Thread 2.2.2Thread 2.2.3 */
#define PCTRL_TCTRL0_EN22 0x00000400
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN22_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN22_EN 0x00000400
/** Control for Processing Element 2, Virtual Machine 1
    This bit controls Virtual Machine 2.1 and the corresponding ThreadsThread 2.1.0Thread 2.1.1Thread 2.1.2Thread 2.1.3 */
#define PCTRL_TCTRL0_EN21 0x00000200
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN21_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN21_EN 0x00000200
/** Control for Processing Element 2, Virtual Machine 0
    This bit controls Virtual Machine 2.0 and the corresponding ThreadsThread 2.0.0Thread 2.0.1Thread 2.0.2Thread 2.0.3 */
#define PCTRL_TCTRL0_EN20 0x00000100
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN20_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN20_EN 0x00000100
/** Control for Processing Element 1, Virtual Machine 2
    This bit controls Virtual Machine 1.2 and the corresponding ThreadsThread 1.2.0Thread 1.2.1Thread 1.2.2Thread 1.2.3 */
#define PCTRL_TCTRL0_EN12 0x00000040
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN12_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN12_EN 0x00000040
/** Control for Processing Element 1, Virtual Machine 1
    This bit controls Virtual Machine 1.1 and the corresponding ThreadsThread 1.1.0Thread 1.1.1Thread 1.1.2Thread 1.1.3 */
#define PCTRL_TCTRL0_EN11 0x00000020
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN11_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN11_EN 0x00000020
/** Control for Processing Element 1, Virtual Machine 0
    This bit controls Virtual Machine 1.0 and the corresponding ThreadsThread 1.0.0Thread 1.0.1Thread 1.0.2Thread 1.0.3 */
#define PCTRL_TCTRL0_EN10 0x00000010
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN10_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN10_EN 0x00000010
/** Control for Processing Element 0, Virtual Machine 2
    This bit controls Virtual Machine 0.2 and the corresponding ThreadsThread 0.2.0Thread 0.2.1Thread 0.2.2Thread 0.2.3 */
#define PCTRL_TCTRL0_EN02 0x00000004
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN02_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN02_EN 0x00000004
/** Control for Processing Element 0, Virtual Machine 1
    This bit controls Virtual Machine 0.1 and the corresponding ThreadsThread 0.1.0Thread 0.1.1Thread 0.1.2Thread 0.1.3 */
#define PCTRL_TCTRL0_EN01 0x00000002
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN01_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN01_EN 0x00000002
/** Control for Processing Element 0, Virtual Machine 0
    This bit controls Virtual Machine 0.0 and the corresponding ThreadsThread 0.0.0Thread 0.0.1Thread 0.0.2Thread 0.0.3 */
#define PCTRL_TCTRL0_EN00 0x00000001
/* Virtual Machine is disabled.
#define PCTRL_TCTRL0_EN00_DIS 0x00000000 */
/** Virtual Machine is enabled. */
#define PCTRL_TCTRL0_EN00_EN 0x00000001

/* Fields of "Thread Status Register" */
/** Status of Processing Element 5, Virtual Machine 2
    This bit represents the status of Virtual Machine 5.2 and the corresponding threadsThread 5.2.0Thread 5.2.1Thread 5.2.2Thread 5.2.3 */
#define PCTRL_TSTAT0_T52 0x00400000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T52_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T52_RUN 0x00400000
/** Status of Processing Element 5, Virtual Machine 1
    This bit represents the status of Virtual Machine 5.1 and the corresponding threadsThread 5.1.0Thread 5.1.1Thread 5.1.2Thread 5.1.3 */
#define PCTRL_TSTAT0_T51 0x00200000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T51_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T51_RUN 0x00200000
/** Status of Processing Element 5, Virtual Machine 0
    This bit represents the status of Virtual Machine 5.0 and the corresponding threadsThread 5.0.0Thread 5.0.1Thread 5.0.2Thread 5.0.3 */
#define PCTRL_TSTAT0_T50 0x00100000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T50_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T50_RUN 0x00100000
/** Status of Processing Element 4, Virtual Machine 2
    This bit represents the status of Virtual Machine 4.2 and the corresponding threadsThread 4.2.0Thread 4.2.1Thread 4.2.2Thread 4.2.3 */
#define PCTRL_TSTAT0_T42 0x00040000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T42_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T42_RUN 0x00040000
/** Status of Processing Element 4, Virtual Machine 1
    This bit represents the status of Virtual Machine 4.1 and the corresponding threadsThread 4.1.0Thread 4.1.1Thread 4.1.2Thread 4.1.3 */
#define PCTRL_TSTAT0_T41 0x00020000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T41_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T41_RUN 0x00020000
/** Status of Processing Element 4, Virtual Machine 0
    This bit represents the status of Virtual Machine 4.0 and the corresponding threadsThread 4.0.0Thread 4.0.1Thread 4.0.2Thread 4.0.3 */
#define PCTRL_TSTAT0_T40 0x00010000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T40_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T40_RUN 0x00010000
/** Status of Processing Element 3, Virtual Machine 2
    This bit represents the status of Virtual Machine 3.2 and the corresponding threadsThread 3.2.0Thread 3.2.1Thread 3.2.2Thread 3.2.3 */
#define PCTRL_TSTAT0_T32 0x00004000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T32_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T32_RUN 0x00004000
/** Status of Processing Element 3, Virtual Machine 1
    This bit represents the status of Virtual Machine 3.1 and the corresponding threadsThread 3.1.0Thread 3.1.1Thread 3.1.2Thread 3.1.3 */
#define PCTRL_TSTAT0_T31 0x00002000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T31_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T31_RUN 0x00002000
/** Status of Processing Element 3, Virtual Machine 0
    This bit represents the status of Virtual Machine 3.0 and the corresponding threadsThread 3.0.0Thread 3.0.1Thread 3.0.2Thread 3.0.3 */
#define PCTRL_TSTAT0_T30 0x00001000
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T30_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T30_RUN 0x00001000
/** Status of Processing Element 2, Virtual Machine 2
    This bit represents the status of Virtual Machine 2.2 and the corresponding threadsThread 2.2.0Thread 2.2.1Thread 2.2.2Thread 2.2.3 */
#define PCTRL_TSTAT0_T22 0x00000400
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T22_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T22_RUN 0x00000400
/** Status of Processing Element 2, Virtual Machine 1
    This bit represents the status of Virtual Machine 2.1 and the corresponding threadsThread 2.1.0Thread 2.1.1Thread 2.1.2Thread 2.1.3 */
#define PCTRL_TSTAT0_T21 0x00000200
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T21_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T21_RUN 0x00000200
/** Status of Processing Element 2, Virtual Machine 0
    This bit represents the status of Virtual Machine 2.0 and the corresponding threadsThread 2.0.0Thread 2.0.1Thread 2.0.2Thread 2.0.3 */
#define PCTRL_TSTAT0_T20 0x00000100
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T20_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T20_RUN 0x00000100
/** Status of Processing Element 1, Virtual Machine 2
    This bit represents the status of Virtual Machine 1.2 and the corresponding threadsThread 1.2.0Thread 1.2.1Thread 1.2.2Thread 1.2.3 */
#define PCTRL_TSTAT0_T12 0x00000040
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T12_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T12_RUN 0x00000040
/** Status of Processing Element 1, Virtual Machine 1
    This bit represents the status of Virtual Machine 1.1 and the corresponding threadsThread 1.1.0Thread 1.1.1Thread 1.1.2Thread 1.1.3 */
#define PCTRL_TSTAT0_T11 0x00000020
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T11_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T11_RUN 0x00000020
/** Status of Processing Element 1, Virtual Machine 0
    This bit represents the status of Virtual Machine 1.0 and the corresponding threadsThread 1.0.0Thread 1.0.1Thread 1.0.2Thread 1.0.3 */
#define PCTRL_TSTAT0_T10 0x00000010
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T10_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T10_RUN 0x00000010
/** Status of Processing Element 0, Virtual Machine 2
    This bit represents the status of Virtual Machine 0.2 and the corresponding threadsThread 0.2.0Thread 0.2.1Thread 0.2.2Thread 0.2.3 */
#define PCTRL_TSTAT0_T02 0x00000004
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T02_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T02_RUN 0x00000004
/** Status of Processing Element 0, Virtual Machine 1
    This bit represents the status of Virtual Machine 0.1 and the corresponding threadsThread 0.1.0Thread 0.1.1Thread 0.1.2Thread 0.1.3 */
#define PCTRL_TSTAT0_T01 0x00000002
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T01_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T01_RUN 0x00000002
/** Status of Processing Element 0, Virtual Machine 0
    This bit represents the status of Virtual Machine 0.0 and the corresponding threadsThread 0.0.0Thread 0.0.1Thread 0.0.2Thread 0.0.3 */
#define PCTRL_TSTAT0_T00 0x00000001
/* Virtual Machine is in idle state.
#define PCTRL_TSTAT0_T00_IDLE 0x00000000 */
/** Virtual Machine is in running state. */
#define PCTRL_TSTAT0_T00_RUN 0x00000001

/* Fields of "Thread Single Step Register" */
/** Single Step Processing Element 5, Virtual Machine 2
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S52 0x00400000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S52_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S52_STEP 0x00400000
/** Single Step Processing Element 5, Virtual Machine 1
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S51 0x00200000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S51_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S51_STEP 0x00200000
/** Single Step Processing Element 5, Virtual Machine 0
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S50 0x00100000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S50_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S50_STEP 0x00100000
/** Single Step Processing Element 4, Virtual Machine 2
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S42 0x00040000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S42_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S42_STEP 0x00040000
/** Single Step Processing Element 4, Virtual Machine 1
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S41 0x00020000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S41_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S41_STEP 0x00020000
/** Single Step Processing Element 4, Virtual Machine 0
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S40 0x00010000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S40_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S40_STEP 0x00010000
/** Single Step Processing Element 3, Virtual Machine 2
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S32 0x00004000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S32_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S32_STEP 0x00004000
/** Single Step Processing Element 3, Virtual Machine 1
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S31 0x00002000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S31_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S31_STEP 0x00002000
/** Single Step Processing Element 3, Virtual Machine 0
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S30 0x00001000
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S30_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S30_STEP 0x00001000
/** Single Step Processing Element 2, Virtual Machine 2
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S22 0x00000400
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S22_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S22_STEP 0x00000400
/** Single Step Processing Element 2, Virtual Machine 1
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S21 0x00000200
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S21_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S21_STEP 0x00000200
/** Single Step Processing Element 2, Virtual Machine 0
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S20 0x00000100
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S20_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S20_STEP 0x00000100
/** Single Step Processing Element 1, Virtual Machine 2
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S12 0x00000040
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S12_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S12_STEP 0x00000040
/** Single Step Processing Element 1, Virtual Machine 1
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S11 0x00000020
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S11_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S11_STEP 0x00000020
/** Single Step Processing Element 1, Virtual Machine 0
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S10 0x00000010
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S10_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S10_STEP 0x00000010
/** Single Step Processing Element 0, Virtual Machine 2
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S02 0x00000004
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S02_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S02_STEP 0x00000004
/** Single Step Processing Element 0, Virtual Machine 1
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S01 0x00000002
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S01_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S01_STEP 0x00000002
/** Single Step Processing Element 0, Virtual Machine 0
    Controls if the actual tread advances one instruction cycle. */
#define PCTRL_TSTEP0_S00 0x00000001
/* The Virtual Machine is not effected.
#define PCTRL_TSTEP0_S00_NOSTEP 0x00000000 */
/** The current thread of the Virtual Machine performs a single instruction step. */
#define PCTRL_TSTEP0_S00_STEP 0x00000001

/* Fields of "Thread Debug Mode Register" */
/** Debug Mode for Processing Element 5, Virtual Machine 2
    This bit controls, if Virtual Machine 5.2 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S52 0x00400000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S52_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S52_DEBUG 0x00400000
/** Debug Mode for Processing Element 5, Virtual Machine 1
    This bit controls, if Virtual Machine 5.1 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S51 0x00200000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S51_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S51_DEBUG 0x00200000
/** Debug Mode for Processing Element 5, Virtual Machine 0
    This bit controls, if Virtual Machine 5.0 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S50 0x00100000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S50_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S50_DEBUG 0x00100000
/** Debug Mode for Processing Element 4, Virtual Machine 2
    This bit controls, if Virtual Machine 4.2 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S42 0x00040000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S42_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S42_DEBUG 0x00040000
/** Debug Mode for Processing Element 4, Virtual Machine 1
    This bit controls, if Virtual Machine 4.1 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S41 0x00020000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S41_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S41_DEBUG 0x00020000
/** Debug Mode for Processing Element 4, Virtual Machine 0
    This bit controls, if Virtual Machine 4.0 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S40 0x00010000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S40_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S40_DEBUG 0x00010000
/** Debug Mode for Processing Element 3, Virtual Machine 2
    This bit controls, if Virtual Machine 3.2 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S32 0x00004000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S32_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S32_DEBUG 0x00004000
/** Debug Mode for Processing Element 3, Virtual Machine 1
    This bit controls, if Virtual Machine 3.1 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S31 0x00002000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S31_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S31_DEBUG 0x00002000
/** Debug Mode for Processing Element 3, Virtual Machine 0
    This bit controls, if Virtual Machine 3.0 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S30 0x00001000
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S30_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S30_DEBUG 0x00001000
/** Debug Mode for Processing Element 2, Virtual Machine 2
    This bit controls, if Virtual Machine 2.2 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S22 0x00000400
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S22_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S22_DEBUG 0x00000400
/** Debug Mode for Processing Element 2, Virtual Machine 1
    This bit controls, if Virtual Machine 2.1 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S21 0x00000200
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S21_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S21_DEBUG 0x00000200
/** Debug Mode for Processing Element 2, Virtual Machine 0
    This bit controls, if Virtual Machine 2.0 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S20 0x00000100
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S20_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S20_DEBUG 0x00000100
/** Debug Mode for Processing Element 1, Virtual Machine 2
    This bit controls, if Virtual Machine 1.2 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S12 0x00000040
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S12_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S12_DEBUG 0x00000040
/** Debug Mode for Processing Element 1, Virtual Machine 1
    This bit controls, if Virtual Machine 1.1 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S11 0x00000020
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S11_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S11_DEBUG 0x00000020
/** Debug Mode for Processing Element 1, Virtual Machine 0
    This bit controls, if Virtual Machine 1.0 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S10 0x00000010
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S10_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S10_DEBUG 0x00000010
/** Debug Mode for Processing Element 0, Virtual Machine 2
    This bit controls, if Virtual Machine 0.2 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S02 0x00000004
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S02_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S02_DEBUG 0x00000004
/** Debug Mode for Processing Element 0, Virtual Machine 1
    This bit controls, if Virtual Machine 0.1 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S01 0x00000002
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S01_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S01_DEBUG 0x00000002
/** Debug Mode for Processing Element 0, Virtual Machine 0
    This bit controls, if Virtual Machine 0.0 is operating in regular mode or debug mode. */
#define PCTRL_TDEBUG0_S00 0x00000001
/* Virtual Machine is in regular mode.
#define PCTRL_TDEBUG0_S00_NODEBUG 0x00000000 */
/** Virtual Machine is in debug mode. */
#define PCTRL_TDEBUG0_S00_DEBUG 0x00000001

/* Fields of "Breakpoint Control Register" */
/** Breakpoint Control for Processing Element 5, Virtual Machine 2
    Breakpoint Enable for all threads of Virtual Machine 5.2. */
#define PCTRL_BCTRL0_T52 0x00400000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T52_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T52_EN 0x00400000
/** Breakpoint Control for Processing Element 5, Virtual Machine 1
    Breakpoint Enable for all threads of Virtual Machine 5.1. */
#define PCTRL_BCTRL0_T51 0x00200000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T51_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T51_EN 0x00200000
/** Breakpoint Control for Processing Element 5, Virtual Machine 0
    Breakpoint Enable for all threads of Virtual Machine 5.0. */
#define PCTRL_BCTRL0_T50 0x00100000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T50_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T50_EN 0x00100000
/** Breakpoint Control for Processing Element 4, Virtual Machine 2
    Breakpoint Enable for all threads of Virtual Machine 4.2. */
#define PCTRL_BCTRL0_T42 0x00040000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T42_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T42_EN 0x00040000
/** Breakpoint Control for Processing Element 4, Virtual Machine 1
    Breakpoint Enable for all threads of Virtual Machine 4.1. */
#define PCTRL_BCTRL0_T41 0x00020000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T41_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T41_EN 0x00020000
/** Breakpoint Control for Processing Element 4, Virtual Machine 0
    Breakpoint Enable for all threads of Virtual Machine 4.0. */
#define PCTRL_BCTRL0_T40 0x00010000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T40_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T40_EN 0x00010000
/** Breakpoint Control for Processing Element 3, Virtual Machine 2
    Breakpoint Enable for all threads of Virtual Machine 3.2. */
#define PCTRL_BCTRL0_T32 0x00004000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T32_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T32_EN 0x00004000
/** Breakpoint Control for Processing Element 3, Virtual Machine 1
    Breakpoint Enable for all threads of Virtual Machine 3.1. */
#define PCTRL_BCTRL0_T31 0x00002000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T31_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T31_EN 0x00002000
/** Breakpoint Control for Processing Element 3, Virtual Machine 0
    Breakpoint Enable for all threads of Virtual Machine 3.0. */
#define PCTRL_BCTRL0_T30 0x00001000
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T30_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T30_EN 0x00001000
/** Breakpoint Control for Processing Element 2, Virtual Machine 2
    Breakpoint Enable for all threads of Virtual Machine 2.2. */
#define PCTRL_BCTRL0_T22 0x00000400
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T22_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T22_EN 0x00000400
/** Breakpoint Control for Processing Element 2, Virtual Machine 1
    Breakpoint Enable for all threads of Virtual Machine 2.1. */
#define PCTRL_BCTRL0_T21 0x00000200
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T21_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T21_EN 0x00000200
/** Breakpoint Control for Processing Element 2, Virtual Machine 0
    Breakpoint Enable for all threads of Virtual Machine 2.0. */
#define PCTRL_BCTRL0_T20 0x00000100
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T20_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T20_EN 0x00000100
/** Breakpoint Control for Processing Element 1, Virtual Machine 2
    Breakpoint Enable for all threads of Virtual Machine 1.2. */
#define PCTRL_BCTRL0_T12 0x00000040
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T12_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T12_EN 0x00000040
/** Breakpoint Control for Processing Element 1, Virtual Machine 1
    Breakpoint Enable for all threads of Virtual Machine 1.1. */
#define PCTRL_BCTRL0_T11 0x00000020
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T11_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T11_EN 0x00000020
/** Breakpoint Control for Processing Element 1, Virtual Machine 0
    Breakpoint Enable for all threads of Virtual Machine 1.0. */
#define PCTRL_BCTRL0_T10 0x00000010
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T10_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T10_EN 0x00000010
/** Breakpoint Control for Processing Element 0, Virtual Machine 2
    Breakpoint Enable for all threads of Virtual Machine 0.2. */
#define PCTRL_BCTRL0_T02 0x00000004
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T02_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T02_EN 0x00000004
/** Breakpoint Control for Processing Element 0, Virtual Machine 1
    Breakpoint Enable for all threads of Virtual Machine 0.1. */
#define PCTRL_BCTRL0_T01 0x00000002
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T01_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T01_EN 0x00000002
/** Breakpoint Control for Processing Element 0, Virtual Machine 0
    Breakpoint Enable for all threads of Virtual Machine 0.0. */
#define PCTRL_BCTRL0_T00 0x00000001
/* Breakpoint for this VM disabled. Ignore BREAK instruction.
#define PCTRL_BCTRL0_T00_DIS 0x00000000 */
/** Breakpoint for this VM enabled. A BREAK instruction will stop the current thread. */
#define PCTRL_BCTRL0_T00_EN 0x00000001

/* Fields of "Breakpoint Status Register" */
/** Breakpoint Status of Processing Element 5, Virtual Machine 2
    Breakpoint Event indication for Virtual Machine 5.2. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T52 0x00400000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T52_NONE 0x00000000 */
/** The current thread of the Virtual Machine 5.2 has hit a breakpoint. */
#define PCTRL_BSTAT0_T52_BSTAT 0x00400000
/** Breakpoint Status of Processing Element 5, Virtual Machine 1
    Breakpoint Event indication for Virtual Machine 5.1. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T51 0x00200000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T51_NONE 0x00000000 */
/** The current thread of the Virtual Machine 5.1 has hit a breakpoint. */
#define PCTRL_BSTAT0_T51_BSTAT 0x00200000
/** Breakpoint Status of Processing Element 5, Virtual Machine 0
    Breakpoint Event indication for Virtual Machine 5.0. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T50 0x00100000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T50_NONE 0x00000000 */
/** The current thread of the Virtual Machine 5.0 has hit a breakpoint. */
#define PCTRL_BSTAT0_T50_BSTAT 0x00100000
/** Breakpoint Status of Processing Element 4, Virtual Machine 2
    Breakpoint Event indication for Virtual Machine 4.2. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T42 0x00040000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T42_NONE 0x00000000 */
/** The current thread of the Virtual Machine 4.2 has hit a breakpoint. */
#define PCTRL_BSTAT0_T42_BSTAT 0x00040000
/** Breakpoint Status of Processing Element 4, Virtual Machine 1
    Breakpoint Event indication for Virtual Machine 4.1. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T41 0x00020000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T41_NONE 0x00000000 */
/** The current thread of the Virtual Machine 4.1 has hit a breakpoint. */
#define PCTRL_BSTAT0_T41_BSTAT 0x00020000
/** Breakpoint Status of Processing Element 4, Virtual Machine 0
    Breakpoint Event indication for Virtual Machine 4.0. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T40 0x00010000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T40_NONE 0x00000000 */
/** The current thread of the Virtual Machine 4.0 has hit a breakpoint. */
#define PCTRL_BSTAT0_T40_BSTAT 0x00010000
/** Breakpoint Status of Processing Element 3, Virtual Machine 2
    Breakpoint Event indication for Virtual Machine 3.2. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T32 0x00004000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T32_NONE 0x00000000 */
/** The current thread of the Virtual Machine 3.2 has hit a breakpoint. */
#define PCTRL_BSTAT0_T32_BSTAT 0x00004000
/** Breakpoint Status of Processing Element 3, Virtual Machine 1
    Breakpoint Event indication for Virtual Machine 3.1. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T31 0x00002000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T31_NONE 0x00000000 */
/** The current thread of the Virtual Machine 3.1 has hit a breakpoint. */
#define PCTRL_BSTAT0_T31_BSTAT 0x00002000
/** Breakpoint Status of Processing Element 3, Virtual Machine 0
    Breakpoint Event indication for Virtual Machine 3.0. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T30 0x00001000
/* No breakpoint hit.
#define PCTRL_BSTAT0_T30_NONE 0x00000000 */
/** The current thread of the Virtual Machine 3.0 has hit a breakpoint. */
#define PCTRL_BSTAT0_T30_BSTAT 0x00001000
/** Breakpoint Status of Processing Element 2, Virtual Machine 2
    Breakpoint Event indication for Virtual Machine 2.2. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T22 0x00000400
/* No breakpoint hit.
#define PCTRL_BSTAT0_T22_NONE 0x00000000 */
/** The current thread of the Virtual Machine 2.2 has hit a breakpoint. */
#define PCTRL_BSTAT0_T22_BSTAT 0x00000400
/** Breakpoint Status of Processing Element 2, Virtual Machine 1
    Breakpoint Event indication for Virtual Machine 2.1. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T21 0x00000200
/* No breakpoint hit.
#define PCTRL_BSTAT0_T21_NONE 0x00000000 */
/** The current thread of the Virtual Machine 2.1 has hit a breakpoint. */
#define PCTRL_BSTAT0_T21_BSTAT 0x00000200
/** Breakpoint Status of Processing Element 2, Virtual Machine 0
    Breakpoint Event indication for Virtual Machine 2.0. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T20 0x00000100
/* No breakpoint hit.
#define PCTRL_BSTAT0_T20_NONE 0x00000000 */
/** The current thread of the Virtual Machine 2.0 has hit a breakpoint. */
#define PCTRL_BSTAT0_T20_BSTAT 0x00000100
/** Breakpoint Status of Processing Element 1, Virtual Machine 2
    Breakpoint Event indication for Virtual Machine 1.2. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T12 0x00000040
/* No breakpoint hit.
#define PCTRL_BSTAT0_T12_NONE 0x00000000 */
/** The current thread of the Virtual Machine 1.2 has hit a breakpoint. */
#define PCTRL_BSTAT0_T12_BSTAT 0x00000040
/** Breakpoint Status of Processing Element 1, Virtual Machine 1
    Breakpoint Event indication for Virtual Machine 1.1. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T11 0x00000020
/* No breakpoint hit.
#define PCTRL_BSTAT0_T11_NONE 0x00000000 */
/** The current thread of the Virtual Machine 1.1 has hit a breakpoint. */
#define PCTRL_BSTAT0_T11_BSTAT 0x00000020
/** Breakpoint Status of Processing Element 1, Virtual Machine 0
    Breakpoint Event indication for Virtual Machine 1.0. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T10 0x00000010
/* No breakpoint hit.
#define PCTRL_BSTAT0_T10_NONE 0x00000000 */
/** The current thread of the Virtual Machine 1.0 has hit a breakpoint. */
#define PCTRL_BSTAT0_T10_BSTAT 0x00000010
/** Breakpoint Status of Processing Element 0, Virtual Machine 2
    Breakpoint Event indication for Virtual Machine 0.2. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T02 0x00000004
/* No breakpoint hit.
#define PCTRL_BSTAT0_T02_NONE 0x00000000 */
/** The current thread of the Virtual Machine 0.2 has hit a breakpoint. */
#define PCTRL_BSTAT0_T02_BSTAT 0x00000004
/** Breakpoint Status of Processing Element 0, Virtual Machine 1
    Breakpoint Event indication for Virtual Machine 0.1. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T01 0x00000002
/* No breakpoint hit.
#define PCTRL_BSTAT0_T01_NONE 0x00000000 */
/** The current thread of the Virtual Machine 0.1 has hit a breakpoint. */
#define PCTRL_BSTAT0_T01_BSTAT 0x00000002
/** Breakpoint Status of Processing Element 0, Virtual Machine 0
    Breakpoint Event indication for Virtual Machine 0.0. Set when a breakpoint is hit and reset when written with a logical one (1). */
#define PCTRL_BSTAT0_T00 0x00000001
/* No breakpoint hit.
#define PCTRL_BSTAT0_T00_NONE 0x00000000 */
/** The current thread of the Virtual Machine 0.0 has hit a breakpoint. */
#define PCTRL_BSTAT0_T00_BSTAT 0x00000001

/* Fields of "Breakpoint Disable Register" */
/** Breakpoint Disable for Processing Element 5, Virtual Machine 2
    Stop Virtual Machine 5.2 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T52 0x00400000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T52_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T52_STOP 0x00400000
/** Breakpoint Disable for Processing Element 5, Virtual Machine 1
    Stop Virtual Machine 5.1 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T51 0x00200000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T51_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T51_STOP 0x00200000
/** Breakpoint Disable for Processing Element 5, Virtual Machine 0
    Stop Virtual Machine 5.0 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T50 0x00100000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T50_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T50_STOP 0x00100000
/** Breakpoint Disable for Processing Element 4, Virtual Machine 2
    Stop Virtual Machine 4.2 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T42 0x00040000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T42_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T42_STOP 0x00040000
/** Breakpoint Disable for Processing Element 4, Virtual Machine 1
    Stop Virtual Machine 4.1 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T41 0x00020000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T41_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T41_STOP 0x00020000
/** Breakpoint Disable for Processing Element 4, Virtual Machine 0
    Stop Virtual Machine 4.0 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T40 0x00010000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T40_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T40_STOP 0x00010000
/** Breakpoint Disable for Processing Element 3, Virtual Machine 2
    Stop Virtual Machine 3.2 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T32 0x00004000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T32_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T32_STOP 0x00004000
/** Breakpoint Disable for Processing Element 3, Virtual Machine 1
    Stop Virtual Machine 3.1 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T31 0x00002000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T31_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T31_STOP 0x00002000
/** Breakpoint Disable for Processing Element 3, Virtual Machine 0
    Stop Virtual Machine 3.0 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T30 0x00001000
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T30_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T30_STOP 0x00001000
/** Breakpoint Disable for Processing Element 2, Virtual Machine 2
    Stop Virtual Machine 2.2 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T22 0x00000400
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T22_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T22_STOP 0x00000400
/** Breakpoint Disable for Processing Element 2, Virtual Machine 1
    Stop Virtual Machine 2.1 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T21 0x00000200
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T21_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T21_STOP 0x00000200
/** Breakpoint Disable for Processing Element 2, Virtual Machine 0
    Stop Virtual Machine 2.0 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T20 0x00000100
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T20_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T20_STOP 0x00000100
/** Breakpoint Disable for Processing Element 1, Virtual Machine 2
    Stop Virtual Machine 1.2 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T12 0x00000040
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T12_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T12_STOP 0x00000040
/** Breakpoint Disable for Processing Element 1, Virtual Machine 1
    Stop Virtual Machine 1.1 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T11 0x00000020
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T11_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T11_STOP 0x00000020
/** Breakpoint Disable for Processing Element 1, Virtual Machine 0
    Stop Virtual Machine 1.0 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T10 0x00000010
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T10_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T10_STOP 0x00000010
/** Breakpoint Disable for Processing Element 0, Virtual Machine 2
    Stop Virtual Machine 0.2 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T02 0x00000004
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T02_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T02_STOP 0x00000004
/** Breakpoint Disable for Processing Element 0, Virtual Machine 1
    Stop Virtual Machine 0.1 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T01 0x00000002
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T01_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T01_STOP 0x00000002
/** Breakpoint Disable for Processing Element 0, Virtual Machine 0
    Stop Virtual Machine 0.0 automatically, when a breakpoint is hit. */
#define PCTRL_BDIS0_T00 0x00000001
/* Virtual Machine is not effected.
#define PCTRL_BDIS0_T00_NOP 0x00000000 */
/** Virtual Machine is stopped automatically when any breakpoint is hit. */
#define PCTRL_BDIS0_T00_STOP 0x00000001

/* Fields of "Interrupt Control Register 0" */
/** Interrupt Enable for Signal 31
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S31 0x80000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S31_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S31_EN 0x80000000
/** Interrupt Enable for Signal 30
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S30 0x40000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S30_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S30_EN 0x40000000
/** Interrupt Enable for Signal 29
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S29 0x20000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S29_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S29_EN 0x20000000
/** Interrupt Enable for Signal 28
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S28 0x10000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S28_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S28_EN 0x10000000
/** Interrupt Enable for Thread 1.2.3
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S27 0x08000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S27_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S27_EN 0x08000000
/** Interrupt Enable for Thread 1.2.2
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S26 0x04000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S26_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S26_EN 0x04000000
/** Interrupt Enable for Thread 1.2.1
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S25 0x02000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S25_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S25_EN 0x02000000
/** Interrupt Enable for Thread 1.2.0
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S24 0x01000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S24_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S24_EN 0x01000000
/** Interrupt Enable for Thread 1.1.3
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S23 0x00800000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S23_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S23_EN 0x00800000
/** Interrupt Enable for Thread 1.1.2
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S22 0x00400000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S22_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S22_EN 0x00400000
/** Interrupt Enable for Thread 1.1.1
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S21 0x00200000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S21_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S21_EN 0x00200000
/** Interrupt Enable for Thread 1.1.0
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S20 0x00100000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S20_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S20_EN 0x00100000
/** Interrupt Enable for Thread 1.0.3
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S19 0x00080000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S19_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S19_EN 0x00080000
/** Interrupt Enable for Thread 1.0.2
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S18 0x00040000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S18_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S18_EN 0x00040000
/** Interrupt Enable for Thread 1.0.1
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S17 0x00020000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S17_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S17_EN 0x00020000
/** Interrupt Enable for Thread 1.0.0
    This bit enables or disables the CPU signal interrupt for PE 1, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S16 0x00010000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S16_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S16_EN 0x00010000
/** Interrupt Enable for Signal 15
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S15 0x00008000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S15_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S15_EN 0x00008000
/** Interrupt Enable for Signal 14
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S14 0x00004000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S14_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S14_EN 0x00004000
/** Interrupt Enable for Signal 13
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S13 0x00002000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S13_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S13_EN 0x00002000
/** Interrupt Enable for Signal 12
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S12 0x00001000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S12_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S12_EN 0x00001000
/** Interrupt Enable for Thread 0.2.3
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S11 0x00000800
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S11_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S11_EN 0x00000800
/** Interrupt Enable for Thread 0.2.2
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S10 0x00000400
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S10_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S10_EN 0x00000400
/** Interrupt Enable for Thread 0.2.1
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S9 0x00000200
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S9_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S9_EN 0x00000200
/** Interrupt Enable for Thread 0.2.0
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S8 0x00000100
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S8_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S8_EN 0x00000100
/** Interrupt Enable for Thread 0.1.3
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S7 0x00000080
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S7_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S7_EN 0x00000080
/** Interrupt Enable for Thread 0.1.2
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S6 0x00000040
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S6_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S6_EN 0x00000040
/** Interrupt Enable for Thread 0.1.1
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S5 0x00000020
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S5_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S5_EN 0x00000020
/** Interrupt Enable for Thread 0.1.0
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S4 0x00000010
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S4_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S4_EN 0x00000010
/** Interrupt Enable for Thread 0.0.3
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S3 0x00000008
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S3_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S3_EN 0x00000008
/** Interrupt Enable for Thread 0.0.2
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S2 0x00000004
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S2_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S2_EN 0x00000004
/** Interrupt Enable for Thread 0.0.1
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S1 0x00000002
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S1_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S1_EN 0x00000002
/** Interrupt Enable for Thread 0.0.0
    This bit enables or disables the CPU signal interrupt for PE 0, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL0_S0 0x00000001
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL0_S0_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL0_S0_EN 0x00000001

/* Fields of "Interrupt Control Register 1" */
/** Interrupt Enable for Signal 63
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S63 0x80000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S63_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S63_EN 0x80000000
/** Interrupt Enable for Signal 62
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S62 0x40000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S62_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S62_EN 0x40000000
/** Interrupt Enable for Signal 61
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S61 0x20000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S61_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S61_EN 0x20000000
/** Interrupt Enable for Signal 60
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S60 0x10000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S60_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S60_EN 0x10000000
/** Interrupt Enable for Thread 3.2.3
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S59 0x08000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S59_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S59_EN 0x08000000
/** Interrupt Enable for Thread 3.2.2
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S58 0x04000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S58_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S58_EN 0x04000000
/** Interrupt Enable for Thread 3.2.1
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S57 0x02000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S57_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S57_EN 0x02000000
/** Interrupt Enable for Thread 3.2.0
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S56 0x01000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S56_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S56_EN 0x01000000
/** Interrupt Enable for Thread 3.1.3
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S55 0x00800000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S55_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S55_EN 0x00800000
/** Interrupt Enable for Thread 3.1.2
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S54 0x00400000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S54_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S54_EN 0x00400000
/** Interrupt Enable for Thread 3.1.1
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S53 0x00200000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S53_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S53_EN 0x00200000
/** Interrupt Enable for Thread 3.1.0
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S52 0x00100000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S52_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S52_EN 0x00100000
/** Interrupt Enable for Thread 3.0.3
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S51 0x00080000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S51_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S51_EN 0x00080000
/** Interrupt Enable for Thread 3.0.2
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S50 0x00040000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S50_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S50_EN 0x00040000
/** Interrupt Enable for Thread 3.0.1
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S49 0x00020000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S49_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S49_EN 0x00020000
/** Interrupt Enable for Thread 3.0.0
    This bit enables or disables the CPU signal interrupt for PE 3, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S48 0x00010000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S48_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S48_EN 0x00010000
/** Interrupt Enable for Signal 47
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S47 0x00008000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S47_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S47_EN 0x00008000
/** Interrupt Enable for Signal 46
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S46 0x00004000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S46_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S46_EN 0x00004000
/** Interrupt Enable for Signal 45
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S45 0x00002000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S45_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S45_EN 0x00002000
/** Interrupt Enable for Signal 44
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S44 0x00001000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S44_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S44_EN 0x00001000
/** Interrupt Enable for Thread 2.2.3
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S43 0x00000800
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S43_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S43_EN 0x00000800
/** Interrupt Enable for Thread 2.2.2
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S42 0x00000400
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S42_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S42_EN 0x00000400
/** Interrupt Enable for Thread 2.2.1
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S41 0x00000200
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S41_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S41_EN 0x00000200
/** Interrupt Enable for Thread 2.2.0
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S40 0x00000100
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S40_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S40_EN 0x00000100
/** Interrupt Enable for Thread 2.1.3
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S39 0x00000080
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S39_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S39_EN 0x00000080
/** Interrupt Enable for Thread 2.1.2
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S38 0x00000040
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S38_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S38_EN 0x00000040
/** Interrupt Enable for Thread 2.1.1
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S37 0x00000020
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S37_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S37_EN 0x00000020
/** Interrupt Enable for Thread 2.1.0
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S36 0x00000010
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S36_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S36_EN 0x00000010
/** Interrupt Enable for Thread 2.0.3
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S35 0x00000008
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S35_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S35_EN 0x00000008
/** Interrupt Enable for Thread 2.0.2
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S34 0x00000004
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S34_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S34_EN 0x00000004
/** Interrupt Enable for Thread 2.0.1
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S33 0x00000002
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S33_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S33_EN 0x00000002
/** Interrupt Enable for Thread 2.0.0
    This bit enables or disables the CPU signal interrupt for PE 2, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL1_S32 0x00000001
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL1_S32_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL1_S32_EN 0x00000001

/* Fields of "Interrupt Control Register 2" */
/** Interrupt Enable for Signal 95
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S95 0x80000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S95_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S95_EN 0x80000000
/** Interrupt Enable for Signal 94
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S94 0x40000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S94_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S94_EN 0x40000000
/** Interrupt Enable for Signal 93
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S93 0x20000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S93_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S93_EN 0x20000000
/** Interrupt Enable for Signal 92
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S92 0x10000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S92_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S92_EN 0x10000000
/** Interrupt Enable for Thread 5.2.3
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S91 0x08000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S91_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S91_EN 0x08000000
/** Interrupt Enable for Thread 5.2.2
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S90 0x04000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S90_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S90_EN 0x04000000
/** Interrupt Enable for Thread 5.2.1
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S89 0x02000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S89_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S89_EN 0x02000000
/** Interrupt Enable for Thread 5.2.0
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S88 0x01000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S88_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S88_EN 0x01000000
/** Interrupt Enable for Thread 5.1.3
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S87 0x00800000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S87_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S87_EN 0x00800000
/** Interrupt Enable for Thread 5.1.2
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S86 0x00400000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S86_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S86_EN 0x00400000
/** Interrupt Enable for Thread 5.1.1
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S85 0x00200000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S85_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S85_EN 0x00200000
/** Interrupt Enable for Thread 5.1.0
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S84 0x00100000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S84_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S84_EN 0x00100000
/** Interrupt Enable for Thread 5.0.3
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S83 0x00080000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S83_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S83_EN 0x00080000
/** Interrupt Enable for Thread 5.0.2
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S82 0x00040000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S82_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S82_EN 0x00040000
/** Interrupt Enable for Thread 5.0.1
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S81 0x00020000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S81_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S81_EN 0x00020000
/** Interrupt Enable for Thread 5.0.0
    This bit enables or disables the CPU signal interrupt for PE 5, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S80 0x00010000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S80_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S80_EN 0x00010000
/** Interrupt Enable for Signal 79
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S79 0x00008000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S79_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S79_EN 0x00008000
/** Interrupt Enable for Signal 78
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S78 0x00004000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S78_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S78_EN 0x00004000
/** Interrupt Enable for Signal 77
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S77 0x00002000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S77_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S77_EN 0x00002000
/** Interrupt Enable for Signal 76
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S76 0x00001000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S76_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S76_EN 0x00001000
/** Interrupt Enable for Thread 4.2.3
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S75 0x00000800
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S75_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S75_EN 0x00000800
/** Interrupt Enable for Thread 4.2.2
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S74 0x00000400
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S74_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S74_EN 0x00000400
/** Interrupt Enable for Thread 4.2.1
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S73 0x00000200
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S73_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S73_EN 0x00000200
/** Interrupt Enable for Thread 4.2.0
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S72 0x00000100
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S72_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S72_EN 0x00000100
/** Interrupt Enable for Thread 4.1.3
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S71 0x00000080
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S71_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S71_EN 0x00000080
/** Interrupt Enable for Thread 4.1.2
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S70 0x00000040
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S70_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S70_EN 0x00000040
/** Interrupt Enable for Thread 4.1.1
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S69 0x00000020
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S69_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S69_EN 0x00000020
/** Interrupt Enable for Thread 4.1.0
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S68 0x00000010
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S68_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S68_EN 0x00000010
/** Interrupt Enable for Thread 4.0.3
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S67 0x00000008
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S67_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S67_EN 0x00000008
/** Interrupt Enable for Thread 4.0.2
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S66 0x00000004
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S66_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S66_EN 0x00000004
/** Interrupt Enable for Thread 4.0.1
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S65 0x00000002
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S65_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S65_EN 0x00000002
/** Interrupt Enable for Thread 4.0.0
    This bit enables or disables the CPU signal interrupt for PE 4, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL2_S64 0x00000001
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL2_S64_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL2_S64_EN 0x00000001

/* Fields of "Interrupt Control Register 3" */
/** Interrupt Enable for Signal 127
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S127 0x80000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S127_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S127_EN 0x80000000
/** Interrupt Enable for Signal 126
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S126 0x40000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S126_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S126_EN 0x40000000
/** Interrupt Enable for Signal 125
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S125 0x20000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S125_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S125_EN 0x20000000
/** Interrupt Enable for Signal 124
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S124 0x10000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S124_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S124_EN 0x10000000
/** Interrupt Enable for Thread 7.2.3
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S123 0x08000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S123_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S123_EN 0x08000000
/** Interrupt Enable for Thread 7.2.2
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S122 0x04000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S122_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S122_EN 0x04000000
/** Interrupt Enable for Thread 7.2.1
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S121 0x02000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S121_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S121_EN 0x02000000
/** Interrupt Enable for Thread 7.2.0
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S120 0x01000000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S120_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S120_EN 0x01000000
/** Interrupt Enable for Thread 7.1.3
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S119 0x00800000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S119_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S119_EN 0x00800000
/** Interrupt Enable for Thread 7.1.2
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S118 0x00400000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S118_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S118_EN 0x00400000
/** Interrupt Enable for Thread 7.1.1
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S117 0x00200000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S117_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S117_EN 0x00200000
/** Interrupt Enable for Thread 7.1.0
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S116 0x00100000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S116_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S116_EN 0x00100000
/** Interrupt Enable for Thread 7.0.3
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S115 0x00080000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S115_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S115_EN 0x00080000
/** Interrupt Enable for Thread 7.0.2
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S114 0x00040000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S114_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S114_EN 0x00040000
/** Interrupt Enable for Thread 7.0.1
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S113 0x00020000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S113_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S113_EN 0x00020000
/** Interrupt Enable for Thread 7.0.0
    This bit enables or disables the CPU signal interrupt for PE 7, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S112 0x00010000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S112_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S112_EN 0x00010000
/** Interrupt Enable for Signal 111
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S111 0x00008000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S111_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S111_EN 0x00008000
/** Interrupt Enable for Signal 110
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S110 0x00004000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S110_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S110_EN 0x00004000
/** Interrupt Enable for Signal 109
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S109 0x00002000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S109_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S109_EN 0x00002000
/** Interrupt Enable for Signal 108
    This bit enables or disables the CPU signal interrupt when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S108 0x00001000
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S108_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S108_EN 0x00001000
/** Interrupt Enable for Thread 6.2.3
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 2, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S107 0x00000800
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S107_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S107_EN 0x00000800
/** Interrupt Enable for Thread 6.2.2
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 2, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S106 0x00000400
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S106_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S106_EN 0x00000400
/** Interrupt Enable for Thread 6.2.1
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 2, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S105 0x00000200
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S105_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S105_EN 0x00000200
/** Interrupt Enable for Thread 6.2.0
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 2, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S104 0x00000100
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S104_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S104_EN 0x00000100
/** Interrupt Enable for Thread 6.1.3
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 1, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S103 0x00000080
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S103_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S103_EN 0x00000080
/** Interrupt Enable for Thread 6.1.2
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 1, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S102 0x00000040
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S102_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S102_EN 0x00000040
/** Interrupt Enable for Thread 6.1.1
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 1, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S101 0x00000020
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S101_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S101_EN 0x00000020
/** Interrupt Enable for Thread 6.1.0
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 1, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S100 0x00000010
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S100_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S100_EN 0x00000010
/** Interrupt Enable for Thread 6.0.3
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 0, Thread 3 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S99 0x00000008
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S99_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S99_EN 0x00000008
/** Interrupt Enable for Thread 6.0.2
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 0, Thread 2 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S98 0x00000004
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S98_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S98_EN 0x00000004
/** Interrupt Enable for Thread 6.0.1
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 0, Thread 1 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S97 0x00000002
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S97_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S97_EN 0x00000002
/** Interrupt Enable for Thread 6.0.0
    This bit enables or disables the CPU signal interrupt for PE 6, Virtual Machine 0, Thread 0 when the corresponding bit in the ISTAT register is set. */
#define PCTRL_ICTRL3_S96 0x00000001
/* Signal does not cause an CPU signal interrupt.
#define PCTRL_ICTRL3_S96_DIS 0x00000000 */
/** Signal causes an CPU interrupt. */
#define PCTRL_ICTRL3_S96_EN 0x00000001

/* Fields of "Interrupt Status Register 0" */
/** Signal 31 Interrupt
    Set when signal 31 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S31 0x80000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S31_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S31_INT 0x80000000
/** Signal 30 Interrupt
    Set when signal 30 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S30 0x40000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S30_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S30_INT 0x40000000
/** Signal 29 Interrupt
    Set when signal 29 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S29 0x20000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S29_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S29_INT 0x20000000
/** Signal 28 Interrupt
    Set when signal 28 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S28 0x10000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S28_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S28_INT 0x10000000
/** Signal Thread 1.2.3 Interrupt
    Set when a signal from PE 1, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S27 0x08000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S27_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S27_INT 0x08000000
/** Signal Thread 1.2.2 Interrupt
    Set when a signal from PE 1, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S26 0x04000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S26_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S26_INT 0x04000000
/** Signal Thread 1.2.1 Interrupt
    Set when a signal from PE 1, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S25 0x02000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S25_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S25_INT 0x02000000
/** Signal Thread 1.2.0 Interrupt
    Set when a signal from PE 1, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S24 0x01000000
/* No interrupt occured.
#define PCTRL_ISTAT0_S24_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S24_INT 0x01000000
/** Signal Thread 1.1.3 Interrupt
    Set when a signal from PE 1, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S23 0x00800000
/* No interrupt occured.
#define PCTRL_ISTAT0_S23_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S23_INT 0x00800000
/** Signal Thread 1.1.2 Interrupt
    Set when a signal from PE 1, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S22 0x00400000
/* No interrupt occured.
#define PCTRL_ISTAT0_S22_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S22_INT 0x00400000
/** Signal Thread 1.1.1 Interrupt
    Set when a signal from PE 1, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S21 0x00200000
/* No interrupt occured.
#define PCTRL_ISTAT0_S21_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S21_INT 0x00200000
/** Signal Thread 1.1.0 Interrupt
    Set when a signal from PE 1, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S20 0x00100000
/* No interrupt occured.
#define PCTRL_ISTAT0_S20_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S20_INT 0x00100000
/** Signal Thread 1.0.3 Interrupt
    Set when a signal from PE 1, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S19 0x00080000
/* No interrupt occured.
#define PCTRL_ISTAT0_S19_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S19_INT 0x00080000
/** Signal Thread 1.0.2 Interrupt
    Set when a signal from PE 1, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S18 0x00040000
/* No interrupt occured.
#define PCTRL_ISTAT0_S18_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S18_INT 0x00040000
/** Signal Thread 1.0.1 Interrupt
    Set when a signal from PE 1, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S17 0x00020000
/* No interrupt occured.
#define PCTRL_ISTAT0_S17_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S17_INT 0x00020000
/** Signal Thread 1.0.0 Interrupt
    Set when a signal from PE 1, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S16 0x00010000
/* No interrupt occured.
#define PCTRL_ISTAT0_S16_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S16_INT 0x00010000
/** Signal 15 Interrupt
    Set when signal 15 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S15 0x00008000
/* No interrupt occured.
#define PCTRL_ISTAT0_S15_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S15_INT 0x00008000
/** Signal 14 Interrupt
    Set when signal 14 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S14 0x00004000
/* No interrupt occured.
#define PCTRL_ISTAT0_S14_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S14_INT 0x00004000
/** Signal 13 Interrupt
    Set when signal 13 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S13 0x00002000
/* No interrupt occured.
#define PCTRL_ISTAT0_S13_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S13_INT 0x00002000
/** Signal 12 Interrupt
    Set when signal 12 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT0_S12 0x00001000
/* No interrupt occured.
#define PCTRL_ISTAT0_S12_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S12_INT 0x00001000
/** Signal Thread 0.2.3 Interrupt
    Set when a signal from PE 0, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S11 0x00000800
/* No interrupt occured.
#define PCTRL_ISTAT0_S11_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S11_INT 0x00000800
/** Signal Thread 0.2.2 Interrupt
    Set when a signal from PE 0, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S10 0x00000400
/* No interrupt occured.
#define PCTRL_ISTAT0_S10_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S10_INT 0x00000400
/** Signal Thread 0.2.1 Interrupt
    Set when a signal from PE 0, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S9 0x00000200
/* No interrupt occured.
#define PCTRL_ISTAT0_S9_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S9_INT 0x00000200
/** Signal Thread 0.2.0 Interrupt
    Set when a signal from PE 0, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S8 0x00000100
/* No interrupt occured.
#define PCTRL_ISTAT0_S8_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S8_INT 0x00000100
/** Signal Thread 0.1.3 Interrupt
    Set when a signal from PE 0, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S7 0x00000080
/* No interrupt occured.
#define PCTRL_ISTAT0_S7_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S7_INT 0x00000080
/** Signal Thread 0.1.2 Interrupt
    Set when a signal from PE 0, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S6 0x00000040
/* No interrupt occured.
#define PCTRL_ISTAT0_S6_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S6_INT 0x00000040
/** Signal Thread 0.1.1 Interrupt
    Set when a signal from PE 0, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S5 0x00000020
/* No interrupt occured.
#define PCTRL_ISTAT0_S5_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S5_INT 0x00000020
/** Signal Thread 0.1.0 Interrupt
    Set when a signal from PE 0, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S4 0x00000010
/* No interrupt occured.
#define PCTRL_ISTAT0_S4_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S4_INT 0x00000010
/** Signal Thread 0.0.3 Interrupt
    Set when a signal from PE 0, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S3 0x00000008
/* No interrupt occured.
#define PCTRL_ISTAT0_S3_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S3_INT 0x00000008
/** Signal Thread 0.0.2 Interrupt
    Set when a signal from PE 0, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S2 0x00000004
/* No interrupt occured.
#define PCTRL_ISTAT0_S2_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S2_INT 0x00000004
/** Signal Thread 0.0.1 Interrupt
    Set when a signal from PE 0, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S1 0x00000002
/* No interrupt occured.
#define PCTRL_ISTAT0_S1_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S1_INT 0x00000002
/** Signal Thread 0.0.0 Interrupt
    Set when a signal from PE 0, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT0_S0 0x00000001
/* No interrupt occured.
#define PCTRL_ISTAT0_S0_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT0_S0_INT 0x00000001

/* Fields of "Interrupt Status Register 1" */
/** Signal 63 Interrupt
    Set when signal 63 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S63 0x80000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S63_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S63_INT 0x80000000
/** Signal 62 Interrupt
    Set when signal 62 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S62 0x40000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S62_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S62_INT 0x40000000
/** Signal 61 Interrupt
    Set when signal 61 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S61 0x20000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S61_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S61_INT 0x20000000
/** Signal 60 Interrupt
    Set when signal 60 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S60 0x10000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S60_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S60_INT 0x10000000
/** Signal Thread 3.2.3 Interrupt
    Set when a signal from PE 3, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S59 0x08000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S59_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S59_INT 0x08000000
/** Signal Thread 3.2.2 Interrupt
    Set when a signal from PE 3, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S58 0x04000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S58_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S58_INT 0x04000000
/** Signal Thread 3.2.1 Interrupt
    Set when a signal from PE 3, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S57 0x02000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S57_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S57_INT 0x02000000
/** Signal Thread 3.2.0 Interrupt
    Set when a signal from PE 3, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S56 0x01000000
/* No interrupt occured.
#define PCTRL_ISTAT1_S56_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S56_INT 0x01000000
/** Signal Thread 3.1.3 Interrupt
    Set when a signal from PE 3, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S55 0x00800000
/* No interrupt occured.
#define PCTRL_ISTAT1_S55_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S55_INT 0x00800000
/** Signal Thread 3.1.2 Interrupt
    Set when a signal from PE 3, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S54 0x00400000
/* No interrupt occured.
#define PCTRL_ISTAT1_S54_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S54_INT 0x00400000
/** Signal Thread 3.1.1 Interrupt
    Set when a signal from PE 3, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S53 0x00200000
/* No interrupt occured.
#define PCTRL_ISTAT1_S53_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S53_INT 0x00200000
/** Signal Thread 3.1.0 Interrupt
    Set when a signal from PE 3, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S52 0x00100000
/* No interrupt occured.
#define PCTRL_ISTAT1_S52_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S52_INT 0x00100000
/** Signal Thread 3.0.3 Interrupt
    Set when a signal from PE 3, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S51 0x00080000
/* No interrupt occured.
#define PCTRL_ISTAT1_S51_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S51_INT 0x00080000
/** Signal Thread 3.0.2 Interrupt
    Set when a signal from PE 3, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S50 0x00040000
/* No interrupt occured.
#define PCTRL_ISTAT1_S50_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S50_INT 0x00040000
/** Signal Thread 3.0.1 Interrupt
    Set when a signal from PE 3, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S49 0x00020000
/* No interrupt occured.
#define PCTRL_ISTAT1_S49_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S49_INT 0x00020000
/** Signal Thread 3.0.0 Interrupt
    Set when a signal from PE 3, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S48 0x00010000
/* No interrupt occured.
#define PCTRL_ISTAT1_S48_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S48_INT 0x00010000
/** Signal 47 Interrupt
    Set when signal 47 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S47 0x00008000
/* No interrupt occured.
#define PCTRL_ISTAT1_S47_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S47_INT 0x00008000
/** Signal 46 Interrupt
    Set when signal 46 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S46 0x00004000
/* No interrupt occured.
#define PCTRL_ISTAT1_S46_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S46_INT 0x00004000
/** Signal 45 Interrupt
    Set when signal 45 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S45 0x00002000
/* No interrupt occured.
#define PCTRL_ISTAT1_S45_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S45_INT 0x00002000
/** Signal 44 Interrupt
    Set when signal 44 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT1_S44 0x00001000
/* No interrupt occured.
#define PCTRL_ISTAT1_S44_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S44_INT 0x00001000
/** Signal Thread 2.2.3 Interrupt
    Set when a signal from PE 2, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S43 0x00000800
/* No interrupt occured.
#define PCTRL_ISTAT1_S43_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S43_INT 0x00000800
/** Signal Thread 2.2.2 Interrupt
    Set when a signal from PE 2, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S42 0x00000400
/* No interrupt occured.
#define PCTRL_ISTAT1_S42_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S42_INT 0x00000400
/** Signal Thread 2.2.1 Interrupt
    Set when a signal from PE 2, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S41 0x00000200
/* No interrupt occured.
#define PCTRL_ISTAT1_S41_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S41_INT 0x00000200
/** Signal Thread 2.2.0 Interrupt
    Set when a signal from PE 2, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S40 0x00000100
/* No interrupt occured.
#define PCTRL_ISTAT1_S40_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S40_INT 0x00000100
/** Signal Thread 2.1.3 Interrupt
    Set when a signal from PE 2, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S39 0x00000080
/* No interrupt occured.
#define PCTRL_ISTAT1_S39_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S39_INT 0x00000080
/** Signal Thread 2.1.2 Interrupt
    Set when a signal from PE 2, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S38 0x00000040
/* No interrupt occured.
#define PCTRL_ISTAT1_S38_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S38_INT 0x00000040
/** Signal Thread 2.1.1 Interrupt
    Set when a signal from PE 2, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S37 0x00000020
/* No interrupt occured.
#define PCTRL_ISTAT1_S37_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S37_INT 0x00000020
/** Signal Thread 2.1.0 Interrupt
    Set when a signal from PE 2, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S36 0x00000010
/* No interrupt occured.
#define PCTRL_ISTAT1_S36_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S36_INT 0x00000010
/** Signal Thread 2.0.3 Interrupt
    Set when a signal from PE 2, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S35 0x00000008
/* No interrupt occured.
#define PCTRL_ISTAT1_S35_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S35_INT 0x00000008
/** Signal Thread 2.0.2 Interrupt
    Set when a signal from PE 2, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S34 0x00000004
/* No interrupt occured.
#define PCTRL_ISTAT1_S34_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S34_INT 0x00000004
/** Signal Thread 2.0.1 Interrupt
    Set when a signal from PE 2, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S33 0x00000002
/* No interrupt occured.
#define PCTRL_ISTAT1_S33_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S33_INT 0x00000002
/** Signal Thread 2.0.0 Interrupt
    Set when a signal from PE 2, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT1_S32 0x00000001
/* No interrupt occured.
#define PCTRL_ISTAT1_S32_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT1_S32_INT 0x00000001

/* Fields of "Interrupt Status Register 2" */
/** Signal 95 Interrupt
    Set when signal 95 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S95 0x80000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S95_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S95_INT 0x80000000
/** Signal 94 Interrupt
    Set when signal 94 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S94 0x40000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S94_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S94_INT 0x40000000
/** Signal 93 Interrupt
    Set when signal 93 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S93 0x20000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S93_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S93_INT 0x20000000
/** Signal 92 Interrupt
    Set when signal 92 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S92 0x10000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S92_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S92_INT 0x10000000
/** Signal Thread 5.2.3 Interrupt
    Set when a signal from PE 5, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S91 0x08000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S91_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S91_INT 0x08000000
/** Signal Thread 5.2.2 Interrupt
    Set when a signal from PE 5, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S90 0x04000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S90_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S90_INT 0x04000000
/** Signal Thread 5.2.1 Interrupt
    Set when a signal from PE 5, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S89 0x02000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S89_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S89_INT 0x02000000
/** Signal Thread 5.2.0 Interrupt
    Set when a signal from PE 5, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S88 0x01000000
/* No interrupt occured.
#define PCTRL_ISTAT2_S88_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S88_INT 0x01000000
/** Signal Thread 5.1.3 Interrupt
    Set when a signal from PE 5, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S87 0x00800000
/* No interrupt occured.
#define PCTRL_ISTAT2_S87_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S87_INT 0x00800000
/** Signal Thread 5.1.2 Interrupt
    Set when a signal from PE 5, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S86 0x00400000
/* No interrupt occured.
#define PCTRL_ISTAT2_S86_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S86_INT 0x00400000
/** Signal Thread 5.1.1 Interrupt
    Set when a signal from PE 5, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S85 0x00200000
/* No interrupt occured.
#define PCTRL_ISTAT2_S85_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S85_INT 0x00200000
/** Signal Thread 5.1.0 Interrupt
    Set when a signal from PE 5, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S84 0x00100000
/* No interrupt occured.
#define PCTRL_ISTAT2_S84_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S84_INT 0x00100000
/** Signal Thread 5.0.3 Interrupt
    Set when a signal from PE 5, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S83 0x00080000
/* No interrupt occured.
#define PCTRL_ISTAT2_S83_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S83_INT 0x00080000
/** Signal Thread 5.0.2 Interrupt
    Set when a signal from PE 5, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S82 0x00040000
/* No interrupt occured.
#define PCTRL_ISTAT2_S82_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S82_INT 0x00040000
/** Signal Thread 5.0.1 Interrupt
    Set when a signal from PE 5, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S81 0x00020000
/* No interrupt occured.
#define PCTRL_ISTAT2_S81_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S81_INT 0x00020000
/** Signal Thread 5.0.0 Interrupt
    Set when a signal from PE 5, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S80 0x00010000
/* No interrupt occured.
#define PCTRL_ISTAT2_S80_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S80_INT 0x00010000
/** Signal 79 Interrupt
    Set when signal 79 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S79 0x00008000
/* No interrupt occured.
#define PCTRL_ISTAT2_S79_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S79_INT 0x00008000
/** Signal 78 Interrupt
    Set when signal 78 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S78 0x00004000
/* No interrupt occured.
#define PCTRL_ISTAT2_S78_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S78_INT 0x00004000
/** Signal 77 Interrupt
    Set when signal 77 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S77 0x00002000
/* No interrupt occured.
#define PCTRL_ISTAT2_S77_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S77_INT 0x00002000
/** Signal 76 Interrupt
    Set when signal 76 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT2_S76 0x00001000
/* No interrupt occured.
#define PCTRL_ISTAT2_S76_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S76_INT 0x00001000
/** Signal Thread 4.2.3 Interrupt
    Set when a signal from PE 4, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S75 0x00000800
/* No interrupt occured.
#define PCTRL_ISTAT2_S75_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S75_INT 0x00000800
/** Signal Thread 4.2.2 Interrupt
    Set when a signal from PE 4, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S74 0x00000400
/* No interrupt occured.
#define PCTRL_ISTAT2_S74_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S74_INT 0x00000400
/** Signal Thread 4.2.1 Interrupt
    Set when a signal from PE 4, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S73 0x00000200
/* No interrupt occured.
#define PCTRL_ISTAT2_S73_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S73_INT 0x00000200
/** Signal Thread 4.2.0 Interrupt
    Set when a signal from PE 4, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S72 0x00000100
/* No interrupt occured.
#define PCTRL_ISTAT2_S72_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S72_INT 0x00000100
/** Signal Thread 4.1.3 Interrupt
    Set when a signal from PE 4, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S71 0x00000080
/* No interrupt occured.
#define PCTRL_ISTAT2_S71_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S71_INT 0x00000080
/** Signal Thread 4.1.2 Interrupt
    Set when a signal from PE 4, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S70 0x00000040
/* No interrupt occured.
#define PCTRL_ISTAT2_S70_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S70_INT 0x00000040
/** Signal Thread 4.1.1 Interrupt
    Set when a signal from PE 4, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S69 0x00000020
/* No interrupt occured.
#define PCTRL_ISTAT2_S69_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S69_INT 0x00000020
/** Signal Thread 4.1.0 Interrupt
    Set when a signal from PE 4, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S68 0x00000010
/* No interrupt occured.
#define PCTRL_ISTAT2_S68_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S68_INT 0x00000010
/** Signal Thread 4.0.3 Interrupt
    Set when a signal from PE 4, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S67 0x00000008
/* No interrupt occured.
#define PCTRL_ISTAT2_S67_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S67_INT 0x00000008
/** Signal Thread 4.0.2 Interrupt
    Set when a signal from PE 4, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S66 0x00000004
/* No interrupt occured.
#define PCTRL_ISTAT2_S66_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S66_INT 0x00000004
/** Signal Thread 4.0.1 Interrupt
    Set when a signal from PE 4, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S65 0x00000002
/* No interrupt occured.
#define PCTRL_ISTAT2_S65_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S65_INT 0x00000002
/** Signal Thread 4.0.0 Interrupt
    Set when a signal from PE 4, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT2_S64 0x00000001
/* No interrupt occured.
#define PCTRL_ISTAT2_S64_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT2_S64_INT 0x00000001

/* Fields of "Interrupt Status Register 3" */
/** Signal 127 Interrupt
    Set when signal 127 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S127 0x80000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S127_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S127_INT 0x80000000
/** Signal 126 Interrupt
    Set when signal 126 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S126 0x40000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S126_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S126_INT 0x40000000
/** Signal 125 Interrupt
    Set when signal 125 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S125 0x20000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S125_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S125_INT 0x20000000
/** Signal 124 Interrupt
    Set when signal 124 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S124 0x10000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S124_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S124_INT 0x10000000
/** Signal Thread 7.2.3 Interrupt
    Set when a signal from PE 7, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S123 0x08000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S123_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S123_INT 0x08000000
/** Signal Thread 7.2.2 Interrupt
    Set when a signal from PE 7, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S122 0x04000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S122_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S122_INT 0x04000000
/** Signal Thread 7.2.1 Interrupt
    Set when a signal from PE 7, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S121 0x02000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S121_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S121_INT 0x02000000
/** Signal Thread 7.2.0 Interrupt
    Set when a signal from PE 7, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S120 0x01000000
/* No interrupt occured.
#define PCTRL_ISTAT3_S120_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S120_INT 0x01000000
/** Signal Thread 7.1.3 Interrupt
    Set when a signal from PE 7, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S119 0x00800000
/* No interrupt occured.
#define PCTRL_ISTAT3_S119_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S119_INT 0x00800000
/** Signal Thread 7.1.2 Interrupt
    Set when a signal from PE 7, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S118 0x00400000
/* No interrupt occured.
#define PCTRL_ISTAT3_S118_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S118_INT 0x00400000
/** Signal Thread 7.1.1 Interrupt
    Set when a signal from PE 7, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S117 0x00200000
/* No interrupt occured.
#define PCTRL_ISTAT3_S117_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S117_INT 0x00200000
/** Signal Thread 7.1.0 Interrupt
    Set when a signal from PE 7, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S116 0x00100000
/* No interrupt occured.
#define PCTRL_ISTAT3_S116_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S116_INT 0x00100000
/** Signal Thread 7.0.3 Interrupt
    Set when a signal from PE 7, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S115 0x00080000
/* No interrupt occured.
#define PCTRL_ISTAT3_S115_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S115_INT 0x00080000
/** Signal Thread 7.0.2 Interrupt
    Set when a signal from PE 7, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S114 0x00040000
/* No interrupt occured.
#define PCTRL_ISTAT3_S114_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S114_INT 0x00040000
/** Signal Thread 7.0.1 Interrupt
    Set when a signal from PE 7, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S113 0x00020000
/* No interrupt occured.
#define PCTRL_ISTAT3_S113_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S113_INT 0x00020000
/** Signal Thread 7.0.0 Interrupt
    Set when a signal from PE 7, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S112 0x00010000
/* No interrupt occured.
#define PCTRL_ISTAT3_S112_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S112_INT 0x00010000
/** Signal 111 Interrupt
    Set when signal 111 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S111 0x00008000
/* No interrupt occured.
#define PCTRL_ISTAT3_S111_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S111_INT 0x00008000
/** Signal 110 Interrupt
    Set when signal 110 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S110 0x00004000
/* No interrupt occured.
#define PCTRL_ISTAT3_S110_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S110_INT 0x00004000
/** Signal 109 Interrupt
    Set when signal 109 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S109 0x00002000
/* No interrupt occured.
#define PCTRL_ISTAT3_S109_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S109_INT 0x00002000
/** Signal 108 Interrupt
    Set when signal 108 has occured. The bit is reset to 0 when written with a logical one. */
#define PCTRL_ISTAT3_S108 0x00001000
/* No interrupt occured.
#define PCTRL_ISTAT3_S108_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S108_INT 0x00001000
/** Signal Thread 6.2.3 Interrupt
    Set when a signal from PE 6, Virtual Machine 2, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S107 0x00000800
/* No interrupt occured.
#define PCTRL_ISTAT3_S107_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S107_INT 0x00000800
/** Signal Thread 6.2.2 Interrupt
    Set when a signal from PE 6, Virtual Machine 2, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S106 0x00000400
/* No interrupt occured.
#define PCTRL_ISTAT3_S106_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S106_INT 0x00000400
/** Signal Thread 6.2.1 Interrupt
    Set when a signal from PE 6, Virtual Machine 2, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S105 0x00000200
/* No interrupt occured.
#define PCTRL_ISTAT3_S105_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S105_INT 0x00000200
/** Signal Thread 6.2.0 Interrupt
    Set when a signal from PE 6, Virtual Machine 2, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S104 0x00000100
/* No interrupt occured.
#define PCTRL_ISTAT3_S104_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S104_INT 0x00000100
/** Signal Thread 6.1.3 Interrupt
    Set when a signal from PE 6, Virtual Machine 1, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S103 0x00000080
/* No interrupt occured.
#define PCTRL_ISTAT3_S103_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S103_INT 0x00000080
/** Signal Thread 6.1.2 Interrupt
    Set when a signal from PE 6, Virtual Machine 1, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S102 0x00000040
/* No interrupt occured.
#define PCTRL_ISTAT3_S102_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S102_INT 0x00000040
/** Signal Thread 6.1.1 Interrupt
    Set when a signal from PE 6, Virtual Machine 1, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S101 0x00000020
/* No interrupt occured.
#define PCTRL_ISTAT3_S101_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S101_INT 0x00000020
/** Signal Thread 6.1.0 Interrupt
    Set when a signal from PE 6, Virtual Machine 1, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S100 0x00000010
/* No interrupt occured.
#define PCTRL_ISTAT3_S100_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S100_INT 0x00000010
/** Signal Thread 6.0.3 Interrupt
    Set when a signal from PE 6, Virtual Machine 0, Thread 3 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S99 0x00000008
/* No interrupt occured.
#define PCTRL_ISTAT3_S99_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S99_INT 0x00000008
/** Signal Thread 6.0.2 Interrupt
    Set when a signal from PE 6, Virtual Machine 0, Thread 2 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S98 0x00000004
/* No interrupt occured.
#define PCTRL_ISTAT3_S98_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S98_INT 0x00000004
/** Signal Thread 6.0.1 Interrupt
    Set when a signal from PE 6, Virtual Machine 0, Thread 1 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S97 0x00000002
/* No interrupt occured.
#define PCTRL_ISTAT3_S97_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S97_INT 0x00000002
/** Signal Thread 6.0.0 Interrupt
    Set when a signal from PE 6, Virtual Machine 0, Thread 0 has occured. Reset when written with a logical one. */
#define PCTRL_ISTAT3_S96 0x00000001
/* No interrupt occured.
#define PCTRL_ISTAT3_S96_NOINT 0x00000000 */
/** Interrupt occured */
#define PCTRL_ISTAT3_S96_INT 0x00000001

/* Fields of "Interrupt Signal Register 0" */
/** Signal 31
    Issue signal 31. */
#define PCTRL_ISIG0_S31 0x80000000
/* No signal is issued.
#define PCTRL_ISIG0_S31_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S31_SIG 0x80000000
/** Signal 30
    Issue signal 30. */
#define PCTRL_ISIG0_S30 0x40000000
/* No signal is issued.
#define PCTRL_ISIG0_S30_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S30_SIG 0x40000000
/** Signal 29
    Issue signal 29. */
#define PCTRL_ISIG0_S29 0x20000000
/* No signal is issued.
#define PCTRL_ISIG0_S29_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S29_SIG 0x20000000
/** Signal 28
    Issue signal 28. */
#define PCTRL_ISIG0_S28 0x10000000
/* No signal is issued.
#define PCTRL_ISIG0_S28_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S28_SIG 0x10000000
/** Signal Thread 1.2.3 Interrupt
    Issue signal for PE 1, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG0_S27 0x08000000
/* No signal is issued.
#define PCTRL_ISIG0_S27_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S27_SIG 0x08000000
/** Signal Thread 1.2.2 Interrupt
    Issue signal for PE 1, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG0_S26 0x04000000
/* No signal is issued.
#define PCTRL_ISIG0_S26_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S26_SIG 0x04000000
/** Signal Thread 1.2.1 Interrupt
    Issue signal for PE 1, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG0_S25 0x02000000
/* No signal is issued.
#define PCTRL_ISIG0_S25_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S25_SIG 0x02000000
/** Signal Thread 1.2.0 Interrupt
    Issue signal for PE 1, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG0_S24 0x01000000
/* No signal is issued.
#define PCTRL_ISIG0_S24_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S24_SIG 0x01000000
/** Signal Thread 1.1.3 Interrupt
    Issue signal for PE 1, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG0_S23 0x00800000
/* No signal is issued.
#define PCTRL_ISIG0_S23_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S23_SIG 0x00800000
/** Signal Thread 1.1.2 Interrupt
    Issue signal for PE 1, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG0_S22 0x00400000
/* No signal is issued.
#define PCTRL_ISIG0_S22_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S22_SIG 0x00400000
/** Signal Thread 1.1.1 Interrupt
    Issue signal for PE 1, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG0_S21 0x00200000
/* No signal is issued.
#define PCTRL_ISIG0_S21_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S21_SIG 0x00200000
/** Signal Thread 1.1.0 Interrupt
    Issue signal for PE 1, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG0_S20 0x00100000
/* No signal is issued.
#define PCTRL_ISIG0_S20_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S20_SIG 0x00100000
/** Signal Thread 1.0.3 Interrupt
    Issue signal for PE 1, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG0_S19 0x00080000
/* No signal is issued.
#define PCTRL_ISIG0_S19_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S19_SIG 0x00080000
/** Signal Thread 1.0.2 Interrupt
    Issue signal for PE 1, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG0_S18 0x00040000
/* No signal is issued.
#define PCTRL_ISIG0_S18_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S18_SIG 0x00040000
/** Signal Thread 1.0.1 Interrupt
    Issue signal for PE 1, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG0_S17 0x00020000
/* No signal is issued.
#define PCTRL_ISIG0_S17_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S17_SIG 0x00020000
/** Signal Thread 1.0.0 Interrupt
    Issue signal for PE 1, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG0_S16 0x00010000
/* No signal is issued.
#define PCTRL_ISIG0_S16_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S16_SIG 0x00010000
/** Signal 15
    Issue signal 15. */
#define PCTRL_ISIG0_S15 0x00008000
/* No signal is issued.
#define PCTRL_ISIG0_S15_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S15_SIG 0x00008000
/** Signal 14
    Issue signal 14. */
#define PCTRL_ISIG0_S14 0x00004000
/* No signal is issued.
#define PCTRL_ISIG0_S14_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S14_SIG 0x00004000
/** Signal 13
    Issue signal 13. */
#define PCTRL_ISIG0_S13 0x00002000
/* No signal is issued.
#define PCTRL_ISIG0_S13_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S13_SIG 0x00002000
/** Signal 12
    Issue signal 12. */
#define PCTRL_ISIG0_S12 0x00001000
/* No signal is issued.
#define PCTRL_ISIG0_S12_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S12_SIG 0x00001000
/** Signal Thread 0.2.3 Interrupt
    Issue signal for PE 0, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG0_S11 0x00000800
/* No signal is issued.
#define PCTRL_ISIG0_S11_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S11_SIG 0x00000800
/** Signal Thread 0.2.2 Interrupt
    Issue signal for PE 0, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG0_S10 0x00000400
/* No signal is issued.
#define PCTRL_ISIG0_S10_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S10_SIG 0x00000400
/** Signal Thread 0.2.1 Interrupt
    Issue signal for PE 0, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG0_S9 0x00000200
/* No signal is issued.
#define PCTRL_ISIG0_S9_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S9_SIG 0x00000200
/** Signal Thread 0.2.0 Interrupt
    Issue signal for PE 0, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG0_S8 0x00000100
/* No signal is issued.
#define PCTRL_ISIG0_S8_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S8_SIG 0x00000100
/** Signal Thread 0.1.3 Interrupt
    Issue signal for PE 0, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG0_S7 0x00000080
/* No signal is issued.
#define PCTRL_ISIG0_S7_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S7_SIG 0x00000080
/** Signal Thread 0.1.2 Interrupt
    Issue signal for PE 0, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG0_S6 0x00000040
/* No signal is issued.
#define PCTRL_ISIG0_S6_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S6_SIG 0x00000040
/** Signal Thread 0.1.1 Interrupt
    Issue signal for PE 0, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG0_S5 0x00000020
/* No signal is issued.
#define PCTRL_ISIG0_S5_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S5_SIG 0x00000020
/** Signal Thread 0.1.0 Interrupt
    Issue signal for PE 0, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG0_S4 0x00000010
/* No signal is issued.
#define PCTRL_ISIG0_S4_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S4_SIG 0x00000010
/** Signal Thread 0.0.3 Interrupt
    Issue signal for PE 0, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG0_S3 0x00000008
/* No signal is issued.
#define PCTRL_ISIG0_S3_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S3_SIG 0x00000008
/** Signal Thread 0.0.2 Interrupt
    Issue signal for PE 0, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG0_S2 0x00000004
/* No signal is issued.
#define PCTRL_ISIG0_S2_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S2_SIG 0x00000004
/** Signal Thread 0.0.1 Interrupt
    Issue signal for PE 0, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG0_S1 0x00000002
/* No signal is issued.
#define PCTRL_ISIG0_S1_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S1_SIG 0x00000002
/** Signal Thread 0.0.0 Interrupt
    Issue signal for PE 0, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG0_S0 0x00000001
/* No signal is issued.
#define PCTRL_ISIG0_S0_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG0_S0_SIG 0x00000001

/* Fields of "Interrupt Signal Register 1" */
/** Signal 63
    Issue signal 63. */
#define PCTRL_ISIG1_S63 0x80000000
/* No signal is issued.
#define PCTRL_ISIG1_S63_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S63_SIG 0x80000000
/** Signal 62
    Issue signal 62. */
#define PCTRL_ISIG1_S62 0x40000000
/* No signal is issued.
#define PCTRL_ISIG1_S62_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S62_SIG 0x40000000
/** Signal 61
    Issue signal 61. */
#define PCTRL_ISIG1_S61 0x20000000
/* No signal is issued.
#define PCTRL_ISIG1_S61_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S61_SIG 0x20000000
/** Signal 60
    Issue signal 60. */
#define PCTRL_ISIG1_S60 0x10000000
/* No signal is issued.
#define PCTRL_ISIG1_S60_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S60_SIG 0x10000000
/** Signal Thread 3.2.3 Interrupt
    Issue signal for PE 3, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG1_S59 0x08000000
/* No signal is issued.
#define PCTRL_ISIG1_S59_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S59_SIG 0x08000000
/** Signal Thread 3.2.2 Interrupt
    Issue signal for PE 3, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG1_S58 0x04000000
/* No signal is issued.
#define PCTRL_ISIG1_S58_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S58_SIG 0x04000000
/** Signal Thread 3.2.1 Interrupt
    Issue signal for PE 3, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG1_S57 0x02000000
/* No signal is issued.
#define PCTRL_ISIG1_S57_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S57_SIG 0x02000000
/** Signal Thread 3.2.0 Interrupt
    Issue signal for PE 3, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG1_S56 0x01000000
/* No signal is issued.
#define PCTRL_ISIG1_S56_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S56_SIG 0x01000000
/** Signal Thread 3.1.3 Interrupt
    Issue signal for PE 3, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG1_S55 0x00800000
/* No signal is issued.
#define PCTRL_ISIG1_S55_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S55_SIG 0x00800000
/** Signal Thread 3.1.2 Interrupt
    Issue signal for PE 3, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG1_S54 0x00400000
/* No signal is issued.
#define PCTRL_ISIG1_S54_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S54_SIG 0x00400000
/** Signal Thread 3.1.1 Interrupt
    Issue signal for PE 3, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG1_S53 0x00200000
/* No signal is issued.
#define PCTRL_ISIG1_S53_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S53_SIG 0x00200000
/** Signal Thread 3.1.0 Interrupt
    Issue signal for PE 3, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG1_S52 0x00100000
/* No signal is issued.
#define PCTRL_ISIG1_S52_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S52_SIG 0x00100000
/** Signal Thread 3.0.3 Interrupt
    Issue signal for PE 3, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG1_S51 0x00080000
/* No signal is issued.
#define PCTRL_ISIG1_S51_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S51_SIG 0x00080000
/** Signal Thread 3.0.2 Interrupt
    Issue signal for PE 3, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG1_S50 0x00040000
/* No signal is issued.
#define PCTRL_ISIG1_S50_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S50_SIG 0x00040000
/** Signal Thread 3.0.1 Interrupt
    Issue signal for PE 3, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG1_S49 0x00020000
/* No signal is issued.
#define PCTRL_ISIG1_S49_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S49_SIG 0x00020000
/** Signal Thread 3.0.0 Interrupt
    Issue signal for PE 3, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG1_S48 0x00010000
/* No signal is issued.
#define PCTRL_ISIG1_S48_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S48_SIG 0x00010000
/** Signal 47
    Issue signal 47. */
#define PCTRL_ISIG1_S47 0x00008000
/* No signal is issued.
#define PCTRL_ISIG1_S47_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S47_SIG 0x00008000
/** Signal 46
    Issue signal 46. */
#define PCTRL_ISIG1_S46 0x00004000
/* No signal is issued.
#define PCTRL_ISIG1_S46_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S46_SIG 0x00004000
/** Signal 45
    Issue signal 45. */
#define PCTRL_ISIG1_S45 0x00002000
/* No signal is issued.
#define PCTRL_ISIG1_S45_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S45_SIG 0x00002000
/** Signal 44
    Issue signal 44. */
#define PCTRL_ISIG1_S44 0x00001000
/* No signal is issued.
#define PCTRL_ISIG1_S44_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S44_SIG 0x00001000
/** Signal Thread 2.2.3 Interrupt
    Issue signal for PE 2, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG1_S43 0x00000800
/* No signal is issued.
#define PCTRL_ISIG1_S43_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S43_SIG 0x00000800
/** Signal Thread 2.2.2 Interrupt
    Issue signal for PE 2, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG1_S42 0x00000400
/* No signal is issued.
#define PCTRL_ISIG1_S42_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S42_SIG 0x00000400
/** Signal Thread 2.2.1 Interrupt
    Issue signal for PE 2, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG1_S41 0x00000200
/* No signal is issued.
#define PCTRL_ISIG1_S41_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S41_SIG 0x00000200
/** Signal Thread 2.2.0 Interrupt
    Issue signal for PE 2, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG1_S40 0x00000100
/* No signal is issued.
#define PCTRL_ISIG1_S40_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S40_SIG 0x00000100
/** Signal Thread 2.1.3 Interrupt
    Issue signal for PE 2, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG1_S39 0x00000080
/* No signal is issued.
#define PCTRL_ISIG1_S39_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S39_SIG 0x00000080
/** Signal Thread 2.1.2 Interrupt
    Issue signal for PE 2, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG1_S38 0x00000040
/* No signal is issued.
#define PCTRL_ISIG1_S38_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S38_SIG 0x00000040
/** Signal Thread 2.1.1 Interrupt
    Issue signal for PE 2, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG1_S37 0x00000020
/* No signal is issued.
#define PCTRL_ISIG1_S37_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S37_SIG 0x00000020
/** Signal Thread 2.1.0 Interrupt
    Issue signal for PE 2, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG1_S36 0x00000010
/* No signal is issued.
#define PCTRL_ISIG1_S36_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S36_SIG 0x00000010
/** Signal Thread 2.0.3 Interrupt
    Issue signal for PE 2, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG1_S35 0x00000008
/* No signal is issued.
#define PCTRL_ISIG1_S35_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S35_SIG 0x00000008
/** Signal Thread 2.0.2 Interrupt
    Issue signal for PE 2, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG1_S34 0x00000004
/* No signal is issued.
#define PCTRL_ISIG1_S34_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S34_SIG 0x00000004
/** Signal Thread 2.0.1 Interrupt
    Issue signal for PE 2, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG1_S33 0x00000002
/* No signal is issued.
#define PCTRL_ISIG1_S33_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S33_SIG 0x00000002
/** Signal Thread 2.0.0 Interrupt
    Issue signal for PE 2, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG1_S32 0x00000001
/* No signal is issued.
#define PCTRL_ISIG1_S32_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG1_S32_SIG 0x00000001

/* Fields of "Interrupt Signal Register 2" */
/** Signal 95
    Issue signal 95. */
#define PCTRL_ISIG2_S95 0x80000000
/* No signal is issued.
#define PCTRL_ISIG2_S95_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S95_SIG 0x80000000
/** Signal 94
    Issue signal 94. */
#define PCTRL_ISIG2_S94 0x40000000
/* No signal is issued.
#define PCTRL_ISIG2_S94_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S94_SIG 0x40000000
/** Signal 93
    Issue signal 93. */
#define PCTRL_ISIG2_S93 0x20000000
/* No signal is issued.
#define PCTRL_ISIG2_S93_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S93_SIG 0x20000000
/** Signal 92
    Issue signal 92. */
#define PCTRL_ISIG2_S92 0x10000000
/* No signal is issued.
#define PCTRL_ISIG2_S92_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S92_SIG 0x10000000
/** Signal Thread 5.2.3 Interrupt
    Issue signal for PE 5, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG2_S91 0x08000000
/* No signal is issued.
#define PCTRL_ISIG2_S91_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S91_SIG 0x08000000
/** Signal Thread 5.2.2 Interrupt
    Issue signal for PE 5, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG2_S90 0x04000000
/* No signal is issued.
#define PCTRL_ISIG2_S90_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S90_SIG 0x04000000
/** Signal Thread 5.2.1 Interrupt
    Issue signal for PE 5, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG2_S89 0x02000000
/* No signal is issued.
#define PCTRL_ISIG2_S89_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S89_SIG 0x02000000
/** Signal Thread 5.2.0 Interrupt
    Issue signal for PE 5, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG2_S88 0x01000000
/* No signal is issued.
#define PCTRL_ISIG2_S88_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S88_SIG 0x01000000
/** Signal Thread 5.1.3 Interrupt
    Issue signal for PE 5, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG2_S87 0x00800000
/* No signal is issued.
#define PCTRL_ISIG2_S87_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S87_SIG 0x00800000
/** Signal Thread 5.1.2 Interrupt
    Issue signal for PE 5, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG2_S86 0x00400000
/* No signal is issued.
#define PCTRL_ISIG2_S86_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S86_SIG 0x00400000
/** Signal Thread 5.1.1 Interrupt
    Issue signal for PE 5, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG2_S85 0x00200000
/* No signal is issued.
#define PCTRL_ISIG2_S85_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S85_SIG 0x00200000
/** Signal Thread 5.1.0 Interrupt
    Issue signal for PE 5, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG2_S84 0x00100000
/* No signal is issued.
#define PCTRL_ISIG2_S84_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S84_SIG 0x00100000
/** Signal Thread 5.0.3 Interrupt
    Issue signal for PE 5, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG2_S83 0x00080000
/* No signal is issued.
#define PCTRL_ISIG2_S83_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S83_SIG 0x00080000
/** Signal Thread 5.0.2 Interrupt
    Issue signal for PE 5, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG2_S82 0x00040000
/* No signal is issued.
#define PCTRL_ISIG2_S82_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S82_SIG 0x00040000
/** Signal Thread 5.0.1 Interrupt
    Issue signal for PE 5, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG2_S81 0x00020000
/* No signal is issued.
#define PCTRL_ISIG2_S81_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S81_SIG 0x00020000
/** Signal Thread 5.0.0 Interrupt
    Issue signal for PE 5, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG2_S80 0x00010000
/* No signal is issued.
#define PCTRL_ISIG2_S80_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S80_SIG 0x00010000
/** Signal 79
    Issue signal 79. */
#define PCTRL_ISIG2_S79 0x00008000
/* No signal is issued.
#define PCTRL_ISIG2_S79_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S79_SIG 0x00008000
/** Signal 78
    Issue signal 78. */
#define PCTRL_ISIG2_S78 0x00004000
/* No signal is issued.
#define PCTRL_ISIG2_S78_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S78_SIG 0x00004000
/** Signal 77
    Issue signal 77. */
#define PCTRL_ISIG2_S77 0x00002000
/* No signal is issued.
#define PCTRL_ISIG2_S77_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S77_SIG 0x00002000
/** Signal 76
    Issue signal 76. */
#define PCTRL_ISIG2_S76 0x00001000
/* No signal is issued.
#define PCTRL_ISIG2_S76_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S76_SIG 0x00001000
/** Signal Thread 4.2.3 Interrupt
    Issue signal for PE 4, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG2_S75 0x00000800
/* No signal is issued.
#define PCTRL_ISIG2_S75_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S75_SIG 0x00000800
/** Signal Thread 4.2.2 Interrupt
    Issue signal for PE 4, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG2_S74 0x00000400
/* No signal is issued.
#define PCTRL_ISIG2_S74_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S74_SIG 0x00000400
/** Signal Thread 4.2.1 Interrupt
    Issue signal for PE 4, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG2_S73 0x00000200
/* No signal is issued.
#define PCTRL_ISIG2_S73_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S73_SIG 0x00000200
/** Signal Thread 4.2.0 Interrupt
    Issue signal for PE 4, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG2_S72 0x00000100
/* No signal is issued.
#define PCTRL_ISIG2_S72_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S72_SIG 0x00000100
/** Signal Thread 4.1.3 Interrupt
    Issue signal for PE 4, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG2_S71 0x00000080
/* No signal is issued.
#define PCTRL_ISIG2_S71_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S71_SIG 0x00000080
/** Signal Thread 4.1.2 Interrupt
    Issue signal for PE 4, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG2_S70 0x00000040
/* No signal is issued.
#define PCTRL_ISIG2_S70_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S70_SIG 0x00000040
/** Signal Thread 4.1.1 Interrupt
    Issue signal for PE 4, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG2_S69 0x00000020
/* No signal is issued.
#define PCTRL_ISIG2_S69_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S69_SIG 0x00000020
/** Signal Thread 4.1.0 Interrupt
    Issue signal for PE 4, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG2_S68 0x00000010
/* No signal is issued.
#define PCTRL_ISIG2_S68_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S68_SIG 0x00000010
/** Signal Thread 4.0.3 Interrupt
    Issue signal for PE 4, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG2_S67 0x00000008
/* No signal is issued.
#define PCTRL_ISIG2_S67_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S67_SIG 0x00000008
/** Signal Thread 4.0.2 Interrupt
    Issue signal for PE 4, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG2_S66 0x00000004
/* No signal is issued.
#define PCTRL_ISIG2_S66_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S66_SIG 0x00000004
/** Signal Thread 4.0.1 Interrupt
    Issue signal for PE 4, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG2_S65 0x00000002
/* No signal is issued.
#define PCTRL_ISIG2_S65_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S65_SIG 0x00000002
/** Signal Thread 4.0.0 Interrupt
    Issue signal for PE 4, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG2_S64 0x00000001
/* No signal is issued.
#define PCTRL_ISIG2_S64_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG2_S64_SIG 0x00000001

/* Fields of "Interrupt Signal Register 3" */
/** Signal 127
    Issue signal 127. */
#define PCTRL_ISIG3_S127 0x80000000
/* No signal is issued.
#define PCTRL_ISIG3_S127_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S127_SIG 0x80000000
/** Signal 126
    Issue signal 126. */
#define PCTRL_ISIG3_S126 0x40000000
/* No signal is issued.
#define PCTRL_ISIG3_S126_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S126_SIG 0x40000000
/** Signal 125
    Issue signal 125. */
#define PCTRL_ISIG3_S125 0x20000000
/* No signal is issued.
#define PCTRL_ISIG3_S125_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S125_SIG 0x20000000
/** Signal 124
    Issue signal 124. */
#define PCTRL_ISIG3_S124 0x10000000
/* No signal is issued.
#define PCTRL_ISIG3_S124_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S124_SIG 0x10000000
/** Signal Thread 7.2.3 Interrupt
    Issue signal for PE 7, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG3_S123 0x08000000
/* No signal is issued.
#define PCTRL_ISIG3_S123_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S123_SIG 0x08000000
/** Signal Thread 7.2.2 Interrupt
    Issue signal for PE 7, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG3_S122 0x04000000
/* No signal is issued.
#define PCTRL_ISIG3_S122_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S122_SIG 0x04000000
/** Signal Thread 7.2.1 Interrupt
    Issue signal for PE 7, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG3_S121 0x02000000
/* No signal is issued.
#define PCTRL_ISIG3_S121_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S121_SIG 0x02000000
/** Signal Thread 7.2.0 Interrupt
    Issue signal for PE 7, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG3_S120 0x01000000
/* No signal is issued.
#define PCTRL_ISIG3_S120_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S120_SIG 0x01000000
/** Signal Thread 7.1.3 Interrupt
    Issue signal for PE 7, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG3_S119 0x00800000
/* No signal is issued.
#define PCTRL_ISIG3_S119_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S119_SIG 0x00800000
/** Signal Thread 7.1.2 Interrupt
    Issue signal for PE 7, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG3_S118 0x00400000
/* No signal is issued.
#define PCTRL_ISIG3_S118_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S118_SIG 0x00400000
/** Signal Thread 7.1.1 Interrupt
    Issue signal for PE 7, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG3_S117 0x00200000
/* No signal is issued.
#define PCTRL_ISIG3_S117_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S117_SIG 0x00200000
/** Signal Thread 7.1.0 Interrupt
    Issue signal for PE 7, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG3_S116 0x00100000
/* No signal is issued.
#define PCTRL_ISIG3_S116_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S116_SIG 0x00100000
/** Signal Thread 7.0.3 Interrupt
    Issue signal for PE 7, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG3_S115 0x00080000
/* No signal is issued.
#define PCTRL_ISIG3_S115_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S115_SIG 0x00080000
/** Signal Thread 7.0.2 Interrupt
    Issue signal for PE 7, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG3_S114 0x00040000
/* No signal is issued.
#define PCTRL_ISIG3_S114_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S114_SIG 0x00040000
/** Signal Thread 7.0.1 Interrupt
    Issue signal for PE 7, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG3_S113 0x00020000
/* No signal is issued.
#define PCTRL_ISIG3_S113_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S113_SIG 0x00020000
/** Signal Thread 7.0.0 Interrupt
    Issue signal for PE 7, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG3_S112 0x00010000
/* No signal is issued.
#define PCTRL_ISIG3_S112_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S112_SIG 0x00010000
/** Signal 111
    Issue signal 111. */
#define PCTRL_ISIG3_S111 0x00008000
/* No signal is issued.
#define PCTRL_ISIG3_S111_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S111_SIG 0x00008000
/** Signal 110
    Issue signal 110. */
#define PCTRL_ISIG3_S110 0x00004000
/* No signal is issued.
#define PCTRL_ISIG3_S110_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S110_SIG 0x00004000
/** Signal 109
    Issue signal 109. */
#define PCTRL_ISIG3_S109 0x00002000
/* No signal is issued.
#define PCTRL_ISIG3_S109_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S109_SIG 0x00002000
/** Signal 108
    Issue signal 108. */
#define PCTRL_ISIG3_S108 0x00001000
/* No signal is issued.
#define PCTRL_ISIG3_S108_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S108_SIG 0x00001000
/** Signal Thread 6.2.3 Interrupt
    Issue signal for PE 6, Virtual Machine 2, Thread 3. */
#define PCTRL_ISIG3_S107 0x00000800
/* No signal is issued.
#define PCTRL_ISIG3_S107_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S107_SIG 0x00000800
/** Signal Thread 6.2.2 Interrupt
    Issue signal for PE 6, Virtual Machine 2, Thread 2. */
#define PCTRL_ISIG3_S106 0x00000400
/* No signal is issued.
#define PCTRL_ISIG3_S106_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S106_SIG 0x00000400
/** Signal Thread 6.2.1 Interrupt
    Issue signal for PE 6, Virtual Machine 2, Thread 1. */
#define PCTRL_ISIG3_S105 0x00000200
/* No signal is issued.
#define PCTRL_ISIG3_S105_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S105_SIG 0x00000200
/** Signal Thread 6.2.0 Interrupt
    Issue signal for PE 6, Virtual Machine 2, Thread 0. */
#define PCTRL_ISIG3_S104 0x00000100
/* No signal is issued.
#define PCTRL_ISIG3_S104_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S104_SIG 0x00000100
/** Signal Thread 6.1.3 Interrupt
    Issue signal for PE 6, Virtual Machine 1, Thread 3. */
#define PCTRL_ISIG3_S103 0x00000080
/* No signal is issued.
#define PCTRL_ISIG3_S103_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S103_SIG 0x00000080
/** Signal Thread 6.1.2 Interrupt
    Issue signal for PE 6, Virtual Machine 1, Thread 2. */
#define PCTRL_ISIG3_S102 0x00000040
/* No signal is issued.
#define PCTRL_ISIG3_S102_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S102_SIG 0x00000040
/** Signal Thread 6.1.1 Interrupt
    Issue signal for PE 6, Virtual Machine 1, Thread 1. */
#define PCTRL_ISIG3_S101 0x00000020
/* No signal is issued.
#define PCTRL_ISIG3_S101_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S101_SIG 0x00000020
/** Signal Thread 6.1.0 Interrupt
    Issue signal for PE 6, Virtual Machine 1, Thread 0. */
#define PCTRL_ISIG3_S100 0x00000010
/* No signal is issued.
#define PCTRL_ISIG3_S100_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S100_SIG 0x00000010
/** Signal Thread 6.0.3 Interrupt
    Issue signal for PE 6, Virtual Machine 0, Thread 3. */
#define PCTRL_ISIG3_S99 0x00000008
/* No signal is issued.
#define PCTRL_ISIG3_S99_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S99_SIG 0x00000008
/** Signal Thread 6.0.2 Interrupt
    Issue signal for PE 6, Virtual Machine 0, Thread 2. */
#define PCTRL_ISIG3_S98 0x00000004
/* No signal is issued.
#define PCTRL_ISIG3_S98_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S98_SIG 0x00000004
/** Signal Thread 6.0.1 Interrupt
    Issue signal for PE 6, Virtual Machine 0, Thread 1. */
#define PCTRL_ISIG3_S97 0x00000002
/* No signal is issued.
#define PCTRL_ISIG3_S97_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S97_SIG 0x00000002
/** Signal Thread 6.0.0 Interrupt
    Issue signal for PE 6, Virtual Machine 0, Thread 0. */
#define PCTRL_ISIG3_S96 0x00000001
/* No signal is issued.
#define PCTRL_ISIG3_S96_NOSIG 0x00000000 */
/** Signal is issued. */
#define PCTRL_ISIG3_S96_SIG 0x00000001

/* Fields of "Timer Control Register" */
/** Timer enable
    This register enables (1) or disables the timer counter (0). */
#define PCTRL_TICTRL_EN 0x00000001

/* Fields of "Timer Compare Register" */
/** Timer compare value
    This register provides the compare value for the timer. When timer reaches this value PEs are informed by interrupt signals. */
#define PCTRL_TICMP_CMP_MASK 0xFFFFFFFF
/** field offset */
#define PCTRL_TICMP_CMP_OFFSET 0

/* Fields of "Timer Data Register" */
/** Timer value
    Read and write the current timer count value. */
#define PCTRL_TIDATA_TIDATA_MASK 0xFFFFFFFF
/** field offset */
#define PCTRL_TIDATA_TIDATA_OFFSET 0

/* Fields of "Timer Interrupt Destination Register 0" */
/** Signal 31
    Issue the signal 31 */
#define PCTRL_TIDMASK0_S31 0x80000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S31_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S31_EN 0x80000000
/** Signal 30
    Issue the signal 30 */
#define PCTRL_TIDMASK0_S30 0x40000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S30_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S30_EN 0x40000000
/** Signal 29
    Issue the signal 29 */
#define PCTRL_TIDMASK0_S29 0x20000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S29_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S29_EN 0x20000000
/** Signal 28
    Issue the signal 28 */
#define PCTRL_TIDMASK0_S28 0x10000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S28_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S28_EN 0x10000000
/** Signal Thread 1.2.3
    Issue signal for PE 1, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK0_S27 0x08000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S27_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S27_EN 0x08000000
/** Signal Thread 1.2.2
    Issue signal for PE 1, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK0_S26 0x04000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S26_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S26_EN 0x04000000
/** Signal Thread 1.2.1
    Issue signal for PE 1, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK0_S25 0x02000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S25_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S25_EN 0x02000000
/** Signal Thread 1.2.0
    Issue signal for PE 1, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK0_S24 0x01000000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S24_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S24_EN 0x01000000
/** Signal Thread 1.1.3
    Issue signal for PE 1, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK0_S23 0x00800000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S23_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S23_EN 0x00800000
/** Signal Thread 1.1.2
    Issue signal for PE 1, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK0_S22 0x00400000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S22_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S22_EN 0x00400000
/** Signal Thread 1.1.1
    Issue signal for PE 1, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK0_S21 0x00200000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S21_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S21_EN 0x00200000
/** Signal Thread 1.1.0
    Issue signal for PE 1, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK0_S20 0x00100000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S20_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S20_EN 0x00100000
/** Signal Thread 1.0.3
    Issue signal for PE 1, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK0_S19 0x00080000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S19_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S19_EN 0x00080000
/** Signal Thread 1.0.2
    Issue signal for PE 1, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK0_S18 0x00040000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S18_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S18_EN 0x00040000
/** Signal Thread 1.0.1
    Issue signal for PE 1, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK0_S17 0x00020000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S17_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S17_EN 0x00020000
/** Signal Thread 1.0.0
    Issue signal for PE 1, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK0_S16 0x00010000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S16_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S16_EN 0x00010000
/** Signal 15
    Issue the signal 15 */
#define PCTRL_TIDMASK0_S15 0x00008000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S15_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S15_EN 0x00008000
/** Signal 14
    Issue the signal 14 */
#define PCTRL_TIDMASK0_S14 0x00004000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S14_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S14_EN 0x00004000
/** Signal 13
    Issue the signal 13 */
#define PCTRL_TIDMASK0_S13 0x00002000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S13_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S13_EN 0x00002000
/** Signal 12
    Issue the signal 12 */
#define PCTRL_TIDMASK0_S12 0x00001000
/* Signal is disabled.
#define PCTRL_TIDMASK0_S12_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S12_EN 0x00001000
/** Signal Thread 0.2.3
    Issue signal for PE 0, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK0_S11 0x00000800
/* Signal is disabled.
#define PCTRL_TIDMASK0_S11_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S11_EN 0x00000800
/** Signal Thread 0.2.2
    Issue signal for PE 0, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK0_S10 0x00000400
/* Signal is disabled.
#define PCTRL_TIDMASK0_S10_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S10_EN 0x00000400
/** Signal Thread 0.2.1
    Issue signal for PE 0, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK0_S9 0x00000200
/* Signal is disabled.
#define PCTRL_TIDMASK0_S9_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S9_EN 0x00000200
/** Signal Thread 0.2.0
    Issue signal for PE 0, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK0_S8 0x00000100
/* Signal is disabled.
#define PCTRL_TIDMASK0_S8_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S8_EN 0x00000100
/** Signal Thread 0.1.3
    Issue signal for PE 0, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK0_S7 0x00000080
/* Signal is disabled.
#define PCTRL_TIDMASK0_S7_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S7_EN 0x00000080
/** Signal Thread 0.1.2
    Issue signal for PE 0, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK0_S6 0x00000040
/* Signal is disabled.
#define PCTRL_TIDMASK0_S6_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S6_EN 0x00000040
/** Signal Thread 0.1.1
    Issue signal for PE 0, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK0_S5 0x00000020
/* Signal is disabled.
#define PCTRL_TIDMASK0_S5_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S5_EN 0x00000020
/** Signal Thread 0.1.0
    Issue signal for PE 0, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK0_S4 0x00000010
/* Signal is disabled.
#define PCTRL_TIDMASK0_S4_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S4_EN 0x00000010
/** Signal Thread 0.0.3
    Issue signal for PE 0, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK0_S3 0x00000008
/* Signal is disabled.
#define PCTRL_TIDMASK0_S3_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S3_EN 0x00000008
/** Signal Thread 0.0.2
    Issue signal for PE 0, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK0_S2 0x00000004
/* Signal is disabled.
#define PCTRL_TIDMASK0_S2_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S2_EN 0x00000004
/** Signal Thread 0.0.1
    Issue signal for PE 0, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK0_S1 0x00000002
/* Signal is disabled.
#define PCTRL_TIDMASK0_S1_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S1_EN 0x00000002
/** Signal Thread 0.0.0
    Issue signal for PE 0, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK0_S0 0x00000001
/* Signal is disabled.
#define PCTRL_TIDMASK0_S0_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK0_S0_EN 0x00000001

/* Fields of "Timer Interrupt Destination Register 1" */
/** Signal 63
    Issue the signal 63 */
#define PCTRL_TIDMASK1_S63 0x80000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S63_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S63_EN 0x80000000
/** Signal 62
    Issue the signal 62 */
#define PCTRL_TIDMASK1_S62 0x40000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S62_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S62_EN 0x40000000
/** Signal 61
    Issue the signal 61 */
#define PCTRL_TIDMASK1_S61 0x20000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S61_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S61_EN 0x20000000
/** Signal 60
    Issue the signal 60 */
#define PCTRL_TIDMASK1_S60 0x10000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S60_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S60_EN 0x10000000
/** Signal Thread 3.2.3
    Issue signal for PE 3, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK1_S59 0x08000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S59_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S59_EN 0x08000000
/** Signal Thread 3.2.2
    Issue signal for PE 3, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK1_S58 0x04000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S58_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S58_EN 0x04000000
/** Signal Thread 3.2.1
    Issue signal for PE 3, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK1_S57 0x02000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S57_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S57_EN 0x02000000
/** Signal Thread 3.2.0
    Issue signal for PE 3, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK1_S56 0x01000000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S56_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S56_EN 0x01000000
/** Signal Thread 3.1.3
    Issue signal for PE 3, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK1_S55 0x00800000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S55_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S55_EN 0x00800000
/** Signal Thread 3.1.2
    Issue signal for PE 3, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK1_S54 0x00400000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S54_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S54_EN 0x00400000
/** Signal Thread 3.1.1
    Issue signal for PE 3, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK1_S53 0x00200000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S53_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S53_EN 0x00200000
/** Signal Thread 3.1.0
    Issue signal for PE 3, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK1_S52 0x00100000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S52_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S52_EN 0x00100000
/** Signal Thread 3.0.3
    Issue signal for PE 3, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK1_S51 0x00080000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S51_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S51_EN 0x00080000
/** Signal Thread 3.0.2
    Issue signal for PE 3, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK1_S50 0x00040000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S50_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S50_EN 0x00040000
/** Signal Thread 3.0.1
    Issue signal for PE 3, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK1_S49 0x00020000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S49_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S49_EN 0x00020000
/** Signal Thread 3.0.0
    Issue signal for PE 3, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK1_S48 0x00010000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S48_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S48_EN 0x00010000
/** Signal 47
    Issue the signal 47 */
#define PCTRL_TIDMASK1_S47 0x00008000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S47_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S47_EN 0x00008000
/** Signal 46
    Issue the signal 46 */
#define PCTRL_TIDMASK1_S46 0x00004000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S46_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S46_EN 0x00004000
/** Signal 45
    Issue the signal 45 */
#define PCTRL_TIDMASK1_S45 0x00002000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S45_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S45_EN 0x00002000
/** Signal 44
    Issue the signal 44 */
#define PCTRL_TIDMASK1_S44 0x00001000
/* Signal is disabled.
#define PCTRL_TIDMASK1_S44_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S44_EN 0x00001000
/** Signal Thread 2.2.3
    Issue signal for PE 2, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK1_S43 0x00000800
/* Signal is disabled.
#define PCTRL_TIDMASK1_S43_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S43_EN 0x00000800
/** Signal Thread 2.2.2
    Issue signal for PE 2, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK1_S42 0x00000400
/* Signal is disabled.
#define PCTRL_TIDMASK1_S42_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S42_EN 0x00000400
/** Signal Thread 2.2.1
    Issue signal for PE 2, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK1_S41 0x00000200
/* Signal is disabled.
#define PCTRL_TIDMASK1_S41_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S41_EN 0x00000200
/** Signal Thread 2.2.0
    Issue signal for PE 2, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK1_S40 0x00000100
/* Signal is disabled.
#define PCTRL_TIDMASK1_S40_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S40_EN 0x00000100
/** Signal Thread 2.1.3
    Issue signal for PE 2, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK1_S39 0x00000080
/* Signal is disabled.
#define PCTRL_TIDMASK1_S39_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S39_EN 0x00000080
/** Signal Thread 2.1.2
    Issue signal for PE 2, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK1_S38 0x00000040
/* Signal is disabled.
#define PCTRL_TIDMASK1_S38_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S38_EN 0x00000040
/** Signal Thread 2.1.1
    Issue signal for PE 2, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK1_S37 0x00000020
/* Signal is disabled.
#define PCTRL_TIDMASK1_S37_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S37_EN 0x00000020
/** Signal Thread 2.1.0
    Issue signal for PE 2, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK1_S36 0x00000010
/* Signal is disabled.
#define PCTRL_TIDMASK1_S36_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S36_EN 0x00000010
/** Signal Thread 2.0.3
    Issue signal for PE 2, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK1_S35 0x00000008
/* Signal is disabled.
#define PCTRL_TIDMASK1_S35_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S35_EN 0x00000008
/** Signal Thread 2.0.2
    Issue signal for PE 2, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK1_S34 0x00000004
/* Signal is disabled.
#define PCTRL_TIDMASK1_S34_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S34_EN 0x00000004
/** Signal Thread 2.0.1
    Issue signal for PE 2, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK1_S33 0x00000002
/* Signal is disabled.
#define PCTRL_TIDMASK1_S33_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S33_EN 0x00000002
/** Signal Thread 2.0.0
    Issue signal for PE 2, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK1_S32 0x00000001
/* Signal is disabled.
#define PCTRL_TIDMASK1_S32_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK1_S32_EN 0x00000001

/* Fields of "Timer Interrupt Destination Register 2" */
/** Signal 95
    Issue the signal 95 */
#define PCTRL_TIDMASK2_S95 0x80000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S95_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S95_EN 0x80000000
/** Signal 94
    Issue the signal 94 */
#define PCTRL_TIDMASK2_S94 0x40000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S94_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S94_EN 0x40000000
/** Signal 93
    Issue the signal 93 */
#define PCTRL_TIDMASK2_S93 0x20000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S93_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S93_EN 0x20000000
/** Signal 92
    Issue the signal 92 */
#define PCTRL_TIDMASK2_S92 0x10000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S92_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S92_EN 0x10000000
/** Signal Thread 5.2.3
    Issue signal for PE 5, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK2_S91 0x08000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S91_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S91_EN 0x08000000
/** Signal Thread 5.2.2
    Issue signal for PE 5, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK2_S90 0x04000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S90_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S90_EN 0x04000000
/** Signal Thread 5.2.1
    Issue signal for PE 5, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK2_S89 0x02000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S89_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S89_EN 0x02000000
/** Signal Thread 5.2.0
    Issue signal for PE 5, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK2_S88 0x01000000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S88_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S88_EN 0x01000000
/** Signal Thread 5.1.3
    Issue signal for PE 5, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK2_S87 0x00800000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S87_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S87_EN 0x00800000
/** Signal Thread 5.1.2
    Issue signal for PE 5, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK2_S86 0x00400000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S86_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S86_EN 0x00400000
/** Signal Thread 5.1.1
    Issue signal for PE 5, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK2_S85 0x00200000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S85_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S85_EN 0x00200000
/** Signal Thread 5.1.0
    Issue signal for PE 5, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK2_S84 0x00100000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S84_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S84_EN 0x00100000
/** Signal Thread 5.0.3
    Issue signal for PE 5, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK2_S83 0x00080000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S83_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S83_EN 0x00080000
/** Signal Thread 5.0.2
    Issue signal for PE 5, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK2_S82 0x00040000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S82_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S82_EN 0x00040000
/** Signal Thread 5.0.1
    Issue signal for PE 5, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK2_S81 0x00020000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S81_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S81_EN 0x00020000
/** Signal Thread 5.0.0
    Issue signal for PE 5, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK2_S80 0x00010000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S80_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S80_EN 0x00010000
/** Signal 79
    Issue the signal 79 */
#define PCTRL_TIDMASK2_S79 0x00008000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S79_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S79_EN 0x00008000
/** Signal 78
    Issue the signal 78 */
#define PCTRL_TIDMASK2_S78 0x00004000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S78_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S78_EN 0x00004000
/** Signal 77
    Issue the signal 77 */
#define PCTRL_TIDMASK2_S77 0x00002000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S77_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S77_EN 0x00002000
/** Signal 76
    Issue the signal 76 */
#define PCTRL_TIDMASK2_S76 0x00001000
/* Signal is disabled.
#define PCTRL_TIDMASK2_S76_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S76_EN 0x00001000
/** Signal Thread 4.2.3
    Issue signal for PE 4, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK2_S75 0x00000800
/* Signal is disabled.
#define PCTRL_TIDMASK2_S75_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S75_EN 0x00000800
/** Signal Thread 4.2.2
    Issue signal for PE 4, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK2_S74 0x00000400
/* Signal is disabled.
#define PCTRL_TIDMASK2_S74_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S74_EN 0x00000400
/** Signal Thread 4.2.1
    Issue signal for PE 4, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK2_S73 0x00000200
/* Signal is disabled.
#define PCTRL_TIDMASK2_S73_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S73_EN 0x00000200
/** Signal Thread 4.2.0
    Issue signal for PE 4, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK2_S72 0x00000100
/* Signal is disabled.
#define PCTRL_TIDMASK2_S72_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S72_EN 0x00000100
/** Signal Thread 4.1.3
    Issue signal for PE 4, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK2_S71 0x00000080
/* Signal is disabled.
#define PCTRL_TIDMASK2_S71_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S71_EN 0x00000080
/** Signal Thread 4.1.2
    Issue signal for PE 4, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK2_S70 0x00000040
/* Signal is disabled.
#define PCTRL_TIDMASK2_S70_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S70_EN 0x00000040
/** Signal Thread 4.1.1
    Issue signal for PE 4, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK2_S69 0x00000020
/* Signal is disabled.
#define PCTRL_TIDMASK2_S69_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S69_EN 0x00000020
/** Signal Thread 4.1.0
    Issue signal for PE 4, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK2_S68 0x00000010
/* Signal is disabled.
#define PCTRL_TIDMASK2_S68_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S68_EN 0x00000010
/** Signal Thread 4.0.3
    Issue signal for PE 4, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK2_S67 0x00000008
/* Signal is disabled.
#define PCTRL_TIDMASK2_S67_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S67_EN 0x00000008
/** Signal Thread 4.0.2
    Issue signal for PE 4, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK2_S66 0x00000004
/* Signal is disabled.
#define PCTRL_TIDMASK2_S66_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S66_EN 0x00000004
/** Signal Thread 4.0.1
    Issue signal for PE 4, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK2_S65 0x00000002
/* Signal is disabled.
#define PCTRL_TIDMASK2_S65_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S65_EN 0x00000002
/** Signal Thread 4.0.0
    Issue signal for PE 4, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK2_S64 0x00000001
/* Signal is disabled.
#define PCTRL_TIDMASK2_S64_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK2_S64_EN 0x00000001

/* Fields of "Timer Interrupt Destination Register 3" */
/** Signal 127
    Issue the signal 127 */
#define PCTRL_TIDMASK3_S127 0x80000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S127_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S127_EN 0x80000000
/** Signal 126
    Issue the signal 126 */
#define PCTRL_TIDMASK3_S126 0x40000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S126_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S126_EN 0x40000000
/** Signal 125
    Issue the signal 125 */
#define PCTRL_TIDMASK3_S125 0x20000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S125_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S125_EN 0x20000000
/** Signal 124
    Issue the signal 124 */
#define PCTRL_TIDMASK3_S124 0x10000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S124_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S124_EN 0x10000000
/** Signal Thread 7.2.3
    Issue signal for PE 7, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK3_S123 0x08000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S123_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S123_EN 0x08000000
/** Signal Thread 7.2.2
    Issue signal for PE 7, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK3_S122 0x04000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S122_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S122_EN 0x04000000
/** Signal Thread 7.2.1
    Issue signal for PE 7, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK3_S121 0x02000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S121_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S121_EN 0x02000000
/** Signal Thread 7.2.0
    Issue signal for PE 7, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK3_S120 0x01000000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S120_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S120_EN 0x01000000
/** Signal Thread 7.1.3
    Issue signal for PE 7, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK3_S119 0x00800000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S119_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S119_EN 0x00800000
/** Signal Thread 7.1.2
    Issue signal for PE 7, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK3_S118 0x00400000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S118_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S118_EN 0x00400000
/** Signal Thread 7.1.1
    Issue signal for PE 7, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK3_S117 0x00200000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S117_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S117_EN 0x00200000
/** Signal Thread 7.1.0
    Issue signal for PE 7, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK3_S116 0x00100000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S116_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S116_EN 0x00100000
/** Signal Thread 7.0.3
    Issue signal for PE 7, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK3_S115 0x00080000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S115_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S115_EN 0x00080000
/** Signal Thread 7.0.2
    Issue signal for PE 7, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK3_S114 0x00040000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S114_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S114_EN 0x00040000
/** Signal Thread 7.0.1
    Issue signal for PE 7, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK3_S113 0x00020000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S113_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S113_EN 0x00020000
/** Signal Thread 7.0.0
    Issue signal for PE 7, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK3_S112 0x00010000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S112_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S112_EN 0x00010000
/** Signal 111
    Issue the signal 111 */
#define PCTRL_TIDMASK3_S111 0x00008000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S111_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S111_EN 0x00008000
/** Signal 110
    Issue the signal 110 */
#define PCTRL_TIDMASK3_S110 0x00004000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S110_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S110_EN 0x00004000
/** Signal 109
    Issue the signal 109 */
#define PCTRL_TIDMASK3_S109 0x00002000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S109_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S109_EN 0x00002000
/** Signal 108
    Issue the signal 108 */
#define PCTRL_TIDMASK3_S108 0x00001000
/* Signal is disabled.
#define PCTRL_TIDMASK3_S108_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S108_EN 0x00001000
/** Signal Thread 6.2.3
    Issue signal for PE 6, Virtual Machine 2, Thread 3. */
#define PCTRL_TIDMASK3_S107 0x00000800
/* Signal is disabled.
#define PCTRL_TIDMASK3_S107_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S107_EN 0x00000800
/** Signal Thread 6.2.2
    Issue signal for PE 6, Virtual Machine 2, Thread 2. */
#define PCTRL_TIDMASK3_S106 0x00000400
/* Signal is disabled.
#define PCTRL_TIDMASK3_S106_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S106_EN 0x00000400
/** Signal Thread 6.2.1
    Issue signal for PE 6, Virtual Machine 2, Thread 1. */
#define PCTRL_TIDMASK3_S105 0x00000200
/* Signal is disabled.
#define PCTRL_TIDMASK3_S105_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S105_EN 0x00000200
/** Signal Thread 6.2.0
    Issue signal for PE 6, Virtual Machine 2, Thread 0. */
#define PCTRL_TIDMASK3_S104 0x00000100
/* Signal is disabled.
#define PCTRL_TIDMASK3_S104_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S104_EN 0x00000100
/** Signal Thread 6.1.3
    Issue signal for PE 6, Virtual Machine 1, Thread 3. */
#define PCTRL_TIDMASK3_S103 0x00000080
/* Signal is disabled.
#define PCTRL_TIDMASK3_S103_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S103_EN 0x00000080
/** Signal Thread 6.1.2
    Issue signal for PE 6, Virtual Machine 1, Thread 2. */
#define PCTRL_TIDMASK3_S102 0x00000040
/* Signal is disabled.
#define PCTRL_TIDMASK3_S102_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S102_EN 0x00000040
/** Signal Thread 6.1.1
    Issue signal for PE 6, Virtual Machine 1, Thread 1. */
#define PCTRL_TIDMASK3_S101 0x00000020
/* Signal is disabled.
#define PCTRL_TIDMASK3_S101_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S101_EN 0x00000020
/** Signal Thread 6.1.0
    Issue signal for PE 6, Virtual Machine 1, Thread 0. */
#define PCTRL_TIDMASK3_S100 0x00000010
/* Signal is disabled.
#define PCTRL_TIDMASK3_S100_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S100_EN 0x00000010
/** Signal Thread 6.0.3
    Issue signal for PE 6, Virtual Machine 0, Thread 3. */
#define PCTRL_TIDMASK3_S99 0x00000008
/* Signal is disabled.
#define PCTRL_TIDMASK3_S99_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S99_EN 0x00000008
/** Signal Thread 6.0.2
    Issue signal for PE 6, Virtual Machine 0, Thread 2. */
#define PCTRL_TIDMASK3_S98 0x00000004
/* Signal is disabled.
#define PCTRL_TIDMASK3_S98_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S98_EN 0x00000004
/** Signal Thread 6.0.1
    Issue signal for PE 6, Virtual Machine 0, Thread 1. */
#define PCTRL_TIDMASK3_S97 0x00000002
/* Signal is disabled.
#define PCTRL_TIDMASK3_S97_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S97_EN 0x00000002
/** Signal Thread 6.0.0
    Issue signal for PE 6, Virtual Machine 0, Thread 0. */
#define PCTRL_TIDMASK3_S96 0x00000001
/* Signal is disabled.
#define PCTRL_TIDMASK3_S96_DIS 0x00000000 */
/** Signal is enabled. */
#define PCTRL_TIDMASK3_S96_EN 0x00000001

/* Fields of "Thread Error Register" */
/** Error for PE 5, Virtual Machine 2
    Indicates a Load-Store error for the PE 5, Virtual Machine 20: no error1: Load-Store error asserted */
#define PCTRL_TERR_E52 0x00400000
/** Error for PE 5, Virtual Machine 1
    Indicates a Load-Store error for the PE 5, Virtual Machine 10: no error1: Load-Store error asserted */
#define PCTRL_TERR_E51 0x00200000
/** Error for PE 5, Virtual Machine 0
    Indicates a Load-Store error for the PE 5, Virtual Machine 00: no error1: Load-Store error asserted */
#define PCTRL_TERR_E50 0x00100000
/** Error for PE 4, Virtual Machine 2
    Indicates a Load-Store error for the PE 4, Virtual Machine 20: no error1: Load-Store error asserted */
#define PCTRL_TERR_E42 0x00040000
/** Error for PE 4, Virtual Machine 1
    Indicates a Load-Store error for the PE 4, Virtual Machine 10: no error1: Load-Store error asserted */
#define PCTRL_TERR_E41 0x00020000
/** Error for PE 4, Virtual Machine 0
    Indicates a Load-Store error for the PE 4, Virtual Machine 00: no error1: Load-Store error asserted */
#define PCTRL_TERR_E40 0x00010000
/** Error for PE 3, Virtual Machine 2
    Indicates a Load-Store error for the PE 3, Virtual Machine 20: no error1: Load-Store error asserted */
#define PCTRL_TERR_E32 0x00004000
/** Error for PE 3, Virtual Machine 1
    Indicates a Load-Store error for the PE 3, Virtual Machine 10: no error1: Load-Store error asserted */
#define PCTRL_TERR_E31 0x00002000
/** Error for PE 3, Virtual Machine 0
    Indicates a Load-Store error for the PE 3, Virtual Machine 00: no error1: Load-Store error asserted */
#define PCTRL_TERR_E30 0x00001000
/** Error for PE 2, Virtual Machine 2
    Indicates a Load-Store error for the PE 2, Virtual Machine 20: no error1: Load-Store error asserted */
#define PCTRL_TERR_E22 0x00000400
/** Error for PE 2, Virtual Machine 1
    Indicates a Load-Store error for the PE 2, Virtual Machine 10: no error1: Load-Store error asserted */
#define PCTRL_TERR_E21 0x00000200
/** Error for PE 2, Virtual Machine 0
    Indicates a Load-Store error for the PE 2, Virtual Machine 00: no error1: Load-Store error asserted */
#define PCTRL_TERR_E20 0x00000100
/** Error for PE 1, Virtual Machine 2
    Indicates a Load-Store error for the PE 1, Virtual Machine 20: no error1: Load-Store error asserted */
#define PCTRL_TERR_E12 0x00000040
/** Error for PE 1, Virtual Machine 1
    Indicates a Load-Store error for the PE 1, Virtual Machine 10: no error1: Load-Store error asserted */
#define PCTRL_TERR_E11 0x00000020
/** Error for PE 1, Virtual Machine 0
    Indicates a Load-Store error for the PE 1, Virtual Machine 00: no error1: Load-Store error asserted */
#define PCTRL_TERR_E10 0x00000010
/** Error for PE 0, Virtual Machine 2
    Indicates a Load-Store error for the PE 0, Virtual Machine 20: no error1: Load-Store error asserted */
#define PCTRL_TERR_E02 0x00000004
/** Error for PE 0, Virtual Machine 1
    Indicates a Load-Store error for the PE 0, Virtual Machine 10: no error1: Load-Store error asserted */
#define PCTRL_TERR_E01 0x00000002
/** Error for PE 0, Virtual Machine 0
    Indicates a Load-Store error for the PE 0, Virtual Machine 00: no error1: Load-Store error asserted */
#define PCTRL_TERR_E00 0x00000001

/* Fields of "Thread Error Interrupt Enable Register" */
/** ERRMASK52
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M52 0x00400000
/** ERRMASK51
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M51 0x00200000
/** ERRMASK50
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M50 0x00100000
/** ERRMASK42
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M42 0x00040000
/** ERRMASK41
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M41 0x00020000
/** ERRMASK40
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M40 0x00010000
/** ERRMASK32
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M32 0x00004000
/** ERRMASK31
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M31 0x00002000
/** ERRMASK30
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M30 0x00001000
/** ERRMASK22
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M22 0x00000400
/** ERRMASK21
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M21 0x00000200
/** ERRMASK20
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M20 0x00000100
/** ERRMASK12
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M12 0x00000040
/** ERRMASK11
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M11 0x00000020
/** ERRMASK10
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M10 0x00000010
/** ERRMASK02
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M02 0x00000004
/** ERRMASK01
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M01 0x00000002
/** ERRMASK00
    Controls, if a corresponding bit in the TERR register generates and ERR Interrupt0: Interrupt disabled1: Interrupt enabled */
#define PCTRL_TERRMASK_M00 0x00000001

/* Fields of "TSE Status Register" */
/** Coprocessor 5 Status
    Inidicates the state of TSE 5. */
#define PCTRL_TSESTAT_S5 0x00000020
/* TSE is in idle state.
#define PCTRL_TSESTAT_S5_IDLE 0x00000000 */
/** TSE is in running state. */
#define PCTRL_TSESTAT_S5_RUN 0x00000020
/** Coprocessor 4 Status
    Inidicates the state of TSE 4. */
#define PCTRL_TSESTAT_S4 0x00000010
/* TSE is in idle state.
#define PCTRL_TSESTAT_S4_IDLE 0x00000000 */
/** TSE is in running state. */
#define PCTRL_TSESTAT_S4_RUN 0x00000010
/** Coprocessor 3 Status
    Inidicates the state of TSE 3. */
#define PCTRL_TSESTAT_S3 0x00000008
/* TSE is in idle state.
#define PCTRL_TSESTAT_S3_IDLE 0x00000000 */
/** TSE is in running state. */
#define PCTRL_TSESTAT_S3_RUN 0x00000008
/** Coprocessor 2 Status
    Inidicates the state of TSE 2. */
#define PCTRL_TSESTAT_S2 0x00000004
/* TSE is in idle state.
#define PCTRL_TSESTAT_S2_IDLE 0x00000000 */
/** TSE is in running state. */
#define PCTRL_TSESTAT_S2_RUN 0x00000004
/** Coprocessor 1 Status
    Inidicates the state of TSE 1. */
#define PCTRL_TSESTAT_S1 0x00000002
/* TSE is in idle state.
#define PCTRL_TSESTAT_S1_IDLE 0x00000000 */
/** TSE is in running state. */
#define PCTRL_TSESTAT_S1_RUN 0x00000002
/** Coprocessor 0 Status
    Inidicates the state of TSE 0. */
#define PCTRL_TSESTAT_S0 0x00000001
/* TSE is in idle state.
#define PCTRL_TSESTAT_S0_IDLE 0x00000000 */
/** TSE is in running state. */
#define PCTRL_TSESTAT_S0_RUN 0x00000001

/* Fields of "TSE Single Step Register" */
/** Single Step one instrcution on TSE 5.
    Controls, if the Coprocessor TSE 5 performs a single instruction step. */
#define PCTRL_TSESTEP_S5 0x00000020
/* no operation
#define PCTRL_TSESTEP_S5_NOP 0x00000000 */
/** TSE performs a single instruction step */
#define PCTRL_TSESTEP_S5_S 0x00000020
/** Single Step one instrcution on TSE 4.
    Controls, if the Coprocessor TSE 4 performs a single instruction step. */
#define PCTRL_TSESTEP_S4 0x00000010
/* no operation
#define PCTRL_TSESTEP_S4_NOP 0x00000000 */
/** TSE performs a single instruction step */
#define PCTRL_TSESTEP_S4_S 0x00000010
/** Single Step one instrcution on TSE 3.
    Controls, if the Coprocessor TSE 3 performs a single instruction step. */
#define PCTRL_TSESTEP_S3 0x00000008
/* no operation
#define PCTRL_TSESTEP_S3_NOP 0x00000000 */
/** TSE performs a single instruction step */
#define PCTRL_TSESTEP_S3_S 0x00000008
/** Single Step one instrcution on TSE 2.
    Controls, if the Coprocessor TSE 2 performs a single instruction step. */
#define PCTRL_TSESTEP_S2 0x00000004
/* no operation
#define PCTRL_TSESTEP_S2_NOP 0x00000000 */
/** TSE performs a single instruction step */
#define PCTRL_TSESTEP_S2_S 0x00000004
/** Single Step one instrcution on TSE 1.
    Controls, if the Coprocessor TSE 1 performs a single instruction step. */
#define PCTRL_TSESTEP_S1 0x00000002
/* no operation
#define PCTRL_TSESTEP_S1_NOP 0x00000000 */
/** TSE performs a single instruction step */
#define PCTRL_TSESTEP_S1_S 0x00000002
/** Single Step one instrcution on TSE 0.
    Controls, if the Coprocessor TSE 0 performs a single instruction step. */
#define PCTRL_TSESTEP_S0 0x00000001
/* no operation
#define PCTRL_TSESTEP_S0_NOP 0x00000000 */
/** TSE performs a single instruction step */
#define PCTRL_TSESTEP_S0_S 0x00000001

/* Fields of "Auxilliary Enable Register" */
/** Enable AUX1 Signal
    0: disabled; 1: enabled. */
#define PCTRL_AUXEN_EN1 0x00000002
/** Enable AUX0 Signal
    0: disabled; 1: enabled. */
#define PCTRL_AUXEN_EN0 0x00000001

/* Fields of "Link Reset Register" */
/** Link D2 Reset
    Resets the state of the Link D2 Network.0: nop1: reset arbiter/network */
#define PCTRL_LINKRST_D2 0x00000008
/** Link D1 Reset
    Resets the state of the Link D1 Network.0: nop1: reset arbiter/network */
#define PCTRL_LINKRST_D1 0x00000004
/** Link C2 Reset
    Resets the state of the Link C2 Network.0: nop1: reset arbiter/network */
#define PCTRL_LINKRST_C2 0x00000002
/** Link C1 Reset
    Resets the state of the Link C1 Network.0: nop1: reset arbiter/network */
#define PCTRL_LINKRST_C1 0x00000001

/* Fields of "Thread Single Step Count Register" */
/** Steps for single stepping
    Defines the number of instructions plus one which are executed for one VM when single stepping is performed via the TSTEP register.NOTE: This register must only be accessed by the debugger kernel. */
#define PCTRL_TSTEPCNT_STEPS_MASK 0x0000FFFF
/** field offset */
#define PCTRL_TSTEPCNT_STEPS_OFFSET 0

/* Fields of "Thread Stop Register" */
/** Stop Processing Element 5, Virtual Machine 2
    This bit controls Virtual Machine 5.2 and the corresponding ThreadsThread 5.2.0Thread 5.2.1Thread 5.2.2Thread 5.2.3 */
#define PCTRL_TSTOP0_STOP52 0x00400000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP52_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP52_STOP 0x00400000
/** Stop Processing Element 5, Virtual Machine 1
    This bit controls Virtual Machine 5.1 and the corresponding ThreadsThread 5.1.0Thread 5.1.1Thread 5.1.2Thread 5.1.3 */
#define PCTRL_TSTOP0_STOP51 0x00200000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP51_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP51_STOP 0x00200000
/** Stop Processing Element 5, Virtual Machine 0
    This bit controls Virtual Machine 5.0 and the corresponding ThreadsThread 5.0.0Thread 5.0.1Thread 5.0.2Thread 5.0.3 */
#define PCTRL_TSTOP0_STOP50 0x00100000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP50_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP50_STOP 0x00100000
/** Stop Processing Element 4, Virtual Machine 2
    This bit controls Virtual Machine 4.2 and the corresponding ThreadsThread 4.2.0Thread 4.2.1Thread 4.2.2Thread 4.2.3 */
#define PCTRL_TSTOP0_STOP42 0x00040000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP42_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP42_STOP 0x00040000
/** Stop Processing Element 4, Virtual Machine 1
    This bit controls Virtual Machine 4.1 and the corresponding ThreadsThread 4.1.0Thread 4.1.1Thread 4.1.2Thread 4.1.3 */
#define PCTRL_TSTOP0_STOP41 0x00020000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP41_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP41_STOP 0x00020000
/** Stop Processing Element 4, Virtual Machine 0
    This bit controls Virtual Machine 4.0 and the corresponding ThreadsThread 4.0.0Thread 4.0.1Thread 4.0.2Thread 4.0.3 */
#define PCTRL_TSTOP0_STOP40 0x00010000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP40_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP40_STOP 0x00010000
/** Stop Processing Element 3, Virtual Machine 2
    This bit controls Virtual Machine 3.2 and the corresponding ThreadsThread 3.2.0Thread 3.2.1Thread 3.2.2Thread 3.2.3 */
#define PCTRL_TSTOP0_STOP32 0x00004000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP32_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP32_STOP 0x00004000
/** Stop Processing Element 3, Virtual Machine 1
    This bit controls Virtual Machine 3.1 and the corresponding ThreadsThread 3.1.0Thread 3.1.1Thread 3.1.2Thread 3.1.3 */
#define PCTRL_TSTOP0_STOP31 0x00002000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP31_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP31_STOP 0x00002000
/** Stop Processing Element 3, Virtual Machine 0
    This bit controls Virtual Machine 3.0 and the corresponding ThreadsThread 3.0.0Thread 3.0.1Thread 3.0.2Thread 3.0.3 */
#define PCTRL_TSTOP0_STOP30 0x00001000
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP30_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP30_STOP 0x00001000
/** Stop Processing Element 2, Virtual Machine 2
    This bit controls Virtual Machine 2.2 and the corresponding ThreadsThread 2.2.0Thread 2.2.1Thread 2.2.2Thread 2.2.3 */
#define PCTRL_TSTOP0_STOP22 0x00000400
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP22_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP22_STOP 0x00000400
/** Stop Processing Element 2, Virtual Machine 1
    This bit controls Virtual Machine 2.1 and the corresponding ThreadsThread 2.1.0Thread 2.1.1Thread 2.1.2Thread 2.1.3 */
#define PCTRL_TSTOP0_STOP21 0x00000200
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP21_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP21_STOP 0x00000200
/** Stop Processing Element 2, Virtual Machine 0
    This bit controls Virtual Machine 2.0 and the corresponding ThreadsThread 2.0.0Thread 2.0.1Thread 2.0.2Thread 2.0.3 */
#define PCTRL_TSTOP0_STOP20 0x00000100
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP20_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP20_STOP 0x00000100
/** Stop Processing Element 1, Virtual Machine 2
    This bit controls Virtual Machine 1.2 and the corresponding ThreadsThread 1.2.0Thread 1.2.1Thread 1.2.2Thread 1.2.3 */
#define PCTRL_TSTOP0_STOP12 0x00000040
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP12_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP12_STOP 0x00000040
/** Stop Processing Element 1, Virtual Machine 1
    This bit controls Virtual Machine 1.1 and the corresponding ThreadsThread 1.1.0Thread 1.1.1Thread 1.1.2Thread 1.1.3 */
#define PCTRL_TSTOP0_STOP11 0x00000020
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP11_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP11_STOP 0x00000020
/** Stop Processing Element 1, Virtual Machine 0
    This bit controls Virtual Machine 1.0 and the corresponding ThreadsThread 1.0.0Thread 1.0.1Thread 1.0.2Thread 1.0.3 */
#define PCTRL_TSTOP0_STOP10 0x00000010
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP10_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP10_STOP 0x00000010
/** Stop Processing Element 0, Virtual Machine 2
    This bit controls Virtual Machine 0.2 and the corresponding ThreadsThread 0.2.0Thread 0.2.1Thread 0.2.2Thread 0.2.3 */
#define PCTRL_TSTOP0_STOP02 0x00000004
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP02_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP02_STOP 0x00000004
/** Stop Processing Element 0, Virtual Machine 1
    This bit controls Virtual Machine 0.1 and the corresponding ThreadsThread 0.1.0Thread 0.1.1Thread 0.1.2Thread 0.1.3 */
#define PCTRL_TSTOP0_STOP01 0x00000002
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP01_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP01_STOP 0x00000002
/** Stop Processing Element 0, Virtual Machine 0
    This bit controls Virtual Machine 0.0 and the corresponding ThreadsThread 0.0.0Thread 0.0.1Thread 0.0.2Thread 0.0.3 */
#define PCTRL_TSTOP0_STOP00 0x00000001
/* Virtual Machine is running depending on the setting in the TCTRL register.
#define PCTRL_TSTOP0_STOP00_NOP 0x00000000 */
/** Virtual Machine is stopped regardless of the setting in the TCTRL register. */
#define PCTRL_TSTOP0_STOP00_STOP 0x00000001

/* Fields of "MBIST Control Register" */
/** Test State for PE 5
    Status of the Program RAM Test Sequence for PE5.0: MBIST not in progress1: MBIST in progress */
#define PCTRL_MCTRL_TS5 0x00200000
/** Test State for PE 4
    Status of the Program RAM Test Sequence for PE4.0: MBIST not in progress1: MBIST in progress */
#define PCTRL_MCTRL_TS4 0x00100000
/** Test State for PE 3
    Status of the Program RAM Test Sequence for PE3.0: MBIST not in progress1: MBIST in progress */
#define PCTRL_MCTRL_TS3 0x00080000
/** Test State for PE 2
    Status of the Program RAM Test Sequence for PE2.0: MBIST not in progress1: MBIST in progress */
#define PCTRL_MCTRL_TS2 0x00040000
/** Test State for PE 1
    Status of the Program RAM Test Sequence for PE1.0: MBIST not in progress1: MBIST in progress */
#define PCTRL_MCTRL_TS1 0x00020000
/** Test State for PE 0
    Status of the Program RAM Test Sequence for PE0.0: MBIST not in progress1: MBIST in progress */
#define PCTRL_MCTRL_TS0 0x00010000
/** Test Mode for PE 5
    Test Mode for PE500: OFF01: READ10: WRITE11: WRITE AND ROTATE */
#define PCTRL_MCTRL_TM5_MASK 0x00000C00
/** field offset */
#define PCTRL_MCTRL_TM5_OFFSET 10
/** Test Mode for PE 4
    Test Mode for PE400: OFF01: READ10: WRITE11: WRITE AND ROTATE */
#define PCTRL_MCTRL_TM4_MASK 0x00000300
/** field offset */
#define PCTRL_MCTRL_TM4_OFFSET 8
/** Test Mode for PE 3
    Test Mode for PE300: OFF01: READ10: WRITE11: WRITE AND ROTATE */
#define PCTRL_MCTRL_TM3_MASK 0x000000C0
/** field offset */
#define PCTRL_MCTRL_TM3_OFFSET 6
/** Test Mode for PE 2
    Test Mode for PE200: OFF01: READ10: WRITE11: WRITE AND ROTATE */
#define PCTRL_MCTRL_TM2_MASK 0x00000030
/** field offset */
#define PCTRL_MCTRL_TM2_OFFSET 4
/** Test Mode for PE 1
    Test Mode for PE100: OFF01: READ10: WRITE11: WRITE AND ROTATE */
#define PCTRL_MCTRL_TM1_MASK 0x0000000C
/** field offset */
#define PCTRL_MCTRL_TM1_OFFSET 2
/** Test Mode for PE 0
    Test Mode for PE000: OFF01: READ10: WRITE11: WRITE AND ROTATE */
#define PCTRL_MCTRL_TM0_MASK 0x00000003
/** field offset */
#define PCTRL_MCTRL_TM0_OFFSET 0

/* Fields of "MBIST Status Register 0" */
/** Test Signature
    Resulting signature of the RAM test. */
#define PCTRL_MSTAT0_SIGNATURE_MASK 0x7FFFFFFF
/** field offset */
#define PCTRL_MSTAT0_SIGNATURE_OFFSET 0

/* Fields of "MBIST Status Register 1" */
/** Test Signature
    Resulting signature of the RAM test. */
#define PCTRL_MSTAT1_SIGNATURE_MASK 0x7FFFFFFF
/** field offset */
#define PCTRL_MSTAT1_SIGNATURE_OFFSET 0

/* Fields of "MBIST Status Register 2" */
/** Test Signature
    Resulting signature of the RAM test. */
#define PCTRL_MSTAT2_SIGNATURE_MASK 0x7FFFFFFF
/** field offset */
#define PCTRL_MSTAT2_SIGNATURE_OFFSET 0

/* Fields of "MBIST Status Register 3" */
/** Test Signature
    Resulting signature of the RAM test. */
#define PCTRL_MSTAT3_SIGNATURE_MASK 0x7FFFFFFF
/** field offset */
#define PCTRL_MSTAT3_SIGNATURE_OFFSET 0

/* Fields of "MBIST Status Register 4" */
/** Test Signature
    Resulting signature of the RAM test. */
#define PCTRL_MSTAT4_SIGNATURE_MASK 0x7FFFFFFF
/** field offset */
#define PCTRL_MSTAT4_SIGNATURE_OFFSET 0

/* Fields of "MBIST Status Register 5" */
/** Test Signature
    Resulting signature of the RAM test. */
#define PCTRL_MSTAT5_SIGNATURE_MASK 0x7FFFFFFF
/** field offset */
#define PCTRL_MSTAT5_SIGNATURE_OFFSET 0

/*! @} */ /* PCTRL_REGISTER */

#endif /* _drv_onu_reg_pctrl_h */
