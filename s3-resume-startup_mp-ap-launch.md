# The S3-Resume `khv_startup_mp` AP-Launch Bug (hypercall `0x0f`)

## What it is

A PS5 hypervisor bug in which **suspend-to-RAM (S3) resume reopens the one-shot AP-startup window**, letting an already-compromised GameOS kernel start an application processor at an attacker-chosen RIP and CR3 while that processor is still executing under the *host* nested-paging root. The AP therefore runs with the hypervisor's physical memory mapped and can read and write every live GameOS VMCB.

Classification: CWE-665 (Improper Initialization), related CWE-863 (Incorrect Authorization). Boundary crossed: compromised GameOS kernel → hypervisor memory.

## Background: why there's a boundary at all

The PS5 hypervisor runs GameOS as a guest and enforces isolation with two nested page table (NPT) roots:

- **Root 0** — the host view. Hypervisor RAM, and the VMCBs, are visible.
- **Root 1** — the GameOS view. Hypervisor memory is unmapped.

Every vcore carries a selector, `vcore_t.cur_npt` at `vcore_t+0xE8`, saying which root applies to it. Normal operation means the guest always runs under root 1. There is also a one-shot `startup_mp` bitmap that gates AP startup: each AP launch spends one bit, and hypercall `0x10` closes the phase entirely.

Hypercall `0x0f` — `khv_startup_mp`, handler at `0x105B0`, `src/svm/hypercall.cpp:446` — is the AP-start primitive. It takes a **logical core, a start RIP, and a CR3 page-table root** from guest registers (`VMMCALL`; id in RAX, args RBX/RCX/RDX). Its only guards are `core < 16` and the one-shot bitmap.

That bitmap is the entire authorization model. It stops a *second* launch. It says nothing about *who* launches first.

## The mechanism

Three separately-reasonable resume decisions compose into the bug.

**1. S3 reinitialization wipes per-core state.** On resume the hypervisor restores its writable state: the `startup_mp` bitmap is cleared, and every newly-initialized `vcore_t` gets `cur_npt = 0` — root 0.

**2. Only the BSP climbs back to root 1.** The transition to the GameOS view is lazy: it happens on the BSP's first GameOS *kernel-text fetch* (inner HV `0x0150d6` writes `vcore.cur_npt = 1`). The BSP takes that fetch during resume. The other fifteen APs are still parked and have fetched nothing, so they sit at `cur_npt == 0` until GameOS wakes them individually.

**3. The hypercall stays callable throughout.** During the interval after `resumectx` has returned but before `acpi_wakeup_cpus` runs the ordinary wake loop, `HCALL 0x0f` is still live and still accepts guest-supplied arguments.

So the window is: **BSP has resumed, APs are at root 0, bitmap is open, hypercall is ungated.**

## The launch

A compromised kernel invokes, inside that window:

```text
HCALL 0x0f(core=15, RIP=0x3ffff000, CR3=0x68000) -> 0
```

Core 15 begins executing at `0x3ffff000` using the supplied CR3. Critically, **it never fetches GameOS kernel text** — nothing in the launch path performs the fetch that would promote it — so it never transitions to root 1. It stays at `cur_npt == 0` and runs with NPT root 0 in effect: the host view, hypervisor RAM mapped.

The `0x68000` CR3 is attacker-supplied and only has to be sufficient for the payload's own needs.

## Two enablers

**A retained executable carrier page.** `0x3ffff000` is not an arbitrary address. The firmware's `bios_mapping` table includes a root-0 **executable identity mapping** whose page ends at `0x40000000`, so that physical page is executable under root 0. It also happens to survive S3 clean. The attacker stages a 4 KiB position-independent payload there before suspending.

**A precisely-timed execution trigger.** The launch has to land in a narrow interval, so the proof arms a debug breakpoint — a `#DB` — at `acpi_sleep_machdep+0x18e`, reached after `resumectx` but before `acpi_wakeup_cpus`. The exception's ROP chain makes the hypercall.

## What the hardware proof demonstrated

From root-0 AP code, the payload walked the inner hypervisor's `pcpus[]` array and converted virtual to physical addresses using the `hv_heap_offset` global — the same conversion `virtualmachine_loop` performs when it hands a VMCB to VMLOAD/VMRUN/VMSAVE:

```text
VMCB physical = pcpu[core].m_vmcb − hv_heap_offset
```

It located all sixteen live GameOS VMCBs (`0x62a57000` … `0x62a75000`, one page each, `sizeof(vmcb_t) = 0x1000`), validated the core index, `NESTED_CTRL == 9`, `Control2 == 1`, and a nonzero aligned `NESTED_CR3` — then performed a **write / read-back / restore** of a reserved qword at `VMCB+0x100` on every core, emitting a success marker only after all sixteen restores verified.

`VMCB+0x100` was chosen because it is inert. The primitive is not field-specific, though, and the same page carries the state that *defines* the boundary:

| Field | Offset | Value |
|---|---|---|
| `NESTED_CTRL` | `+0x90` | `9` (nested paging enable \| GMET enable) |
| `NESTED_CR3` | `+0xb0` | active nested page table root |
| `Control2` | `+0xb8` | `1` |

A write primitive to the VMCB page is a write primitive to the nested-paging root, which is what actually enforces GameOS/hypervisor separation. The proof deliberately left all three untouched.

## Scope and limits

- **Preconditions are real.** This requires prior GameOS kernel read/write plus ROP or kernel-call capability. It is a boundary crossing *after* kernel compromise, not an unprivileged entry point.
- **13.60 is static-only.** The mechanism survives — HCALL `0x0f` still dispatches through the table at inner `0x183e8` to the AP-start path, the `bios_mapping` table is byte-identical across its full `0xc0` bytes, and `pcpus[]`/`m_vmcb+0xa8`/`core_id+0x138` are unchanged. But `hv_heap_offset` moved (`0x2a048` → `0x2a028`) and the allocation geometry differs, so the 10.00 binary is not portable; a 13.60 port must derive its aliases dynamically. Verdict: *mechanism yes, existing artifact no.*

## Remediation

1. Do not clear or reopen `startup_mp` on S3 after GameOS has already taken ownership of AP startup.
2. Bind `HCALL 0x0f` to an authenticated hypervisor-controlled resume phase; reject GameOS calls outside the expected wake operation.
3. Stop accepting arbitrary RIP and CR3 from the resumed guest — bind them to the expected kernel AP entry and an approved page-table root.
4. Assign the final GameOS NPT to an AP *before* transferring control to any guest-supplied RIP. No AP should execute attacker-selected code at `cur_npt == 0`.
5. Ensure root 0 cannot map hypervisor/VMCB physical pages through guest-controlled page tables, and enforce protection for CPU-origin accesses, not just DMA.


## Greetings

Greetings to flat_z, specter, j0rdy, zecoxao, earthonion, TorusHV, theflow, bollarz, and Dr. Yenyen.
