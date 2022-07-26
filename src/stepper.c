/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <capstone.h>
#include <glib.h>

#include "config.h"
#include "vmi.h"
#include "signal.h"

#ifdef HAVE_XEN
#include <xenctrl.h>
xc_interface *xc;
#endif

vmi_instance_t vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
addr_t stop_rip;
bool loopmode, reset, stop_on_cpuid, stop_on_sysret, stop_on_breakpoint, print_hex, print_regs;
int interrupted;
unsigned long limit, count;
csh cs_handle;
page_mode_t pm;

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
    printf("\t --limit <singlestep count>\n");
    printf("\t --loopmode\n");
    printf("\t --stop-on-cpuid\n");
    printf("\t --stop-on-sysret\n");
    printf("\t --stop-on-breakpoint\n");
    printf("\t --stop-on-address <addr>\n");
    printf("\t --reset\n");
    printf("\t --print-hex\n");
    printf("\t --print-regs\n");
}

bool prefix(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

void
vmi_print_hex1(
    const unsigned char *data,
    unsigned long length)
{
    unsigned long i, j, numrows, index;

    numrows = (length + 15) >> 4;

    for (i = 0; i < numrows; ++i) {
        /* print the first 8 hex values */
        for (j = 0; j < 8; ++j) {
            index = i * 16 + j;
            if (index < length) {
                printf("%.2x ", data[index]);
            } else {
                printf("   ");
            }
        }
        printf(" ");

        /* print the second 8 hex values */
        for (; j < 16; ++j) {
            index = i * 16 + j;
            if (index < length) {
                printf("%.2x ", data[index]);
            } else {
                printf("   ");
            }
        }
        // printf("\n");
        printf(";");
    }
}

static bool print_instruction(vmi_instance_t _vmi, addr_t cr3, addr_t addr, x86_registers_t *regs)
{
    unsigned char buf[15] = {0};
    cs_insn *insn = NULL;
    size_t read = 0, insn_count = 0;
    const char *format = print_hex ? "%s" : "%s\n";
    bool stop = false;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .pt = cr3,
        .addr = addr
    );

    vmi_read(_vmi, &ctx, 15, buf, &read);

    if ( read )
        insn_count = cs_disasm(cs_handle, buf, read, 0, 0, &insn);

    //printf("%5lu: %16lx  ", count, addr);
    printf("%16lx;", addr);

    if ( insn_count )
    {
        gchar *str;
        char operand_str[160];

        if (strlen(insn[0].op_str) == 0)
            strncpy(operand_str, " ", 160);
        else
            strncpy(operand_str, insn[0].op_str, 160);
        
        if (prefix("call", insn[0].mnemonic)) {
            // relative offset
            unsigned long ul_offset = strtoul(insn[0].op_str, NULL, 0);
            // printf("relative offset in decimal: %ld\n", ul_offset);
            // printf("destination addr: %016lx\n", ul_offset + regs->rip);
            
            char dest_str[256];
            sprintf(dest_str, "%016lx", ul_offset + regs->rip);
            //str = g_strconcat(insn[0].mnemonic, " ", insn[0].op_str, " (dest: ", dest_str, ")", NULL);
            //str = g_strconcat(insn[0].mnemonic, " ", insn[0].op_str, NULL);
            str = g_strconcat(insn[0].mnemonic, ";", operand_str, ";", NULL);
        } else {
            //str =
             g_strconcat(insn[0].mnemonic, " ", insn[0].op_str, NULL);
            str = g_strconcat(insn[0].mnemonic, ";", operand_str, ";", NULL);
        }

        printf(format, str);
        g_free(str);

        if ( stop_on_cpuid && insn[0].id == X86_INS_CPUID )
            stop = true;
        else if ( stop_on_sysret && insn[0].id == X86_INS_SYSRET )
            stop = true;
        else if ( stop_on_breakpoint && insn[0].id == X86_INS_INT3 )
            stop = true;
        else if ( insn[0].id == X86_INS_HLT )
            stop = true;

        if ( print_hex ) {
            vmi_print_hex1(buf, insn[0].size);
            if (insn[0].size == 0) {
                printf("ERROR\n");
            }
            //vmi_print_hex(buf, read);
        }

        cs_free(insn, insn_count);
    }
    else
        printf(format, "-");


    return stop;
}

static void print_registers(x86_registers_t *regs)
{
    if ( !print_regs )
        return;

    printf("RAX=0x%016lx,RBX=0x%016lx,", regs->rax, regs->rbx);
    printf("RBP=0x%016lx,RSP=0x%016lx,", regs->rbp, regs->rsp);
    printf("RDI=0x%016lx,RSI=0x%016lx,", regs->rdi, regs->rsi);
    printf("RDX=0x%016lx,RCX=0x%016lx,", regs->rdx, regs->rcx);
    printf("R8=0x%016lx,R9=0x%016lx,", regs->r8, regs->r9);
    printf("R10=0x%016lx,R11=0x%016lx,", regs->r10, regs->r11);
    printf("R12=0x%016lx,R13=0x%016lx,", regs->r12, regs->r13);
    printf("R14=0x%016lx,R15=0x%016lx,", regs->r14, regs->r15);
    printf("CR0=0x%016lx,CR2=0x%016lx,", regs->cr0, regs->cr2);
    printf("CR3=0x%016lx,CR4=0x%016lx\n", regs->cr3, regs->cr4);
}

static event_response_t tracer_cb(vmi_instance_t _vmi, vmi_event_t *event)
{
    bool cpuid = false;
    bool sysret = false;
    bool breakpoint = false;

    count++;

    bool stop = print_instruction(_vmi, event->x86_regs->cr3, event->x86_regs->rip, event->x86_regs);
    print_registers(event->x86_regs);

    if ( stop || count >= limit || event->x86_regs->rip == stop_rip )
    {
        interrupted = 1;
        vmi_pause_vm(_vmi);
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    return 0;
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"limit", required_argument, NULL, 'L'},
        {"loopmode", no_argument, NULL, 'l'},
        {"reset", no_argument, NULL, 'r'},
        {"print-hex", no_argument, NULL, 'x'},
        {"print-regs", no_argument, NULL, 'R'},
        {"stop-on-cpuid", no_argument, NULL, 's'},
        {"stop-on-sysret", no_argument, NULL, 't'},
        {"stop-on-breakpoint", no_argument, NULL, 'b'},
        {"stop-on-address", required_argument, NULL, 'S'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:L:S:hlrstb";
    uint32_t domid = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
            case 'd':
                domid = strtoul(optarg, NULL, 0);
                break;
            case 'L':
                limit = strtoull(optarg, NULL, 0);
                break;
            case 'l':
                loopmode = true;
                break;
            case 'r':
                reset = true;
                break;
            case 's':
                stop_on_cpuid = true;
                break;
            case 't':
                stop_on_sysret = true;
                break;
            case 'b':
                stop_on_breakpoint = true;
                break;
            case 'x':
                print_hex = true;
                break;
            case 'R':
                print_regs = true;
                break;
            case 'S':
                stop_rip = strtoull(optarg, NULL, 0);
                break;
            case 'h': /* fall-through */
            default:
                usage();
                return -1;
        };
    }

    if ( !domid || !limit )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, NULL, domid, NULL, NULL, true, true) )
        return -1;

#ifdef HAVE_XEN
    if ( !(xc = xc_interface_open(0, 0, 0)) )
        goto done;

    if ( reset && xc_memshr_fork_reset(xc, domid) )
    {
        printf("Failed to reset VM, is it a fork?\n");
        goto done;
    }
#endif

    if ( cs_open(CS_ARCH_X86, pm == VMI_PM_IA32E ? CS_MODE_64 : CS_MODE_32, &cs_handle) )
        goto done;

    setup_handlers();

    registers_t regs = {0};
    vmi_event_t singlestep_event;
    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, tracer_cb, 1);

    do
    {
        vmi_get_vcpuregs(vmi, &regs, 0);

        print_instruction(vmi, regs.x86.cr3, regs.x86.rip, &regs.x86);
        print_registers(&regs.x86);

        vmi_toggle_single_step_vcpu(vmi, &singlestep_event, 0, 1);

        vmi_resume_vm(vmi);
        while ( !interrupted && VMI_SUCCESS == vmi_events_listen(vmi, 500) )
        {}

        vmi_pause_vm(vmi);
        vmi_events_listen(vmi, 0);
        vmi_toggle_single_step_vcpu(vmi, &singlestep_event, 0, 0);

        if ( loopmode )
        {
            vmi_pagecache_flush(vmi);

#ifdef HAVE_XEN
            if ( xc_memshr_fork_reset(xc, domid) )
            {
                printf("Failed to reset VM, is it a fork?\n");
                break;
            }
#endif

            printf("----------------------------------------\n");
        }

        vmi_resume_vm(vmi);

        interrupted = 0;
        count = 0;

        /*
         * Loopmode here is useful to check whether something causes divergence in the path
         * after a reset. There shouldn't be any divergence since after a reset the fork
         * should resume from the same state as before.
         */
    }
    while ( loopmode );

done:

#ifdef HAVE_XEN
    if ( xc )
        xc_interface_close(xc);
#endif

    cs_close(&cs_handle);
    vmi_destroy(vmi);

    return 0;
}
