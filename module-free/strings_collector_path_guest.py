"""Codex real kernel capture test of owned synthetic ASCII objects at guard pages."""

from pathlib import Path
import subprocess, hashlib, json, shutil

R = __import__("settings").ROOT
E = R / "evidence/string-controls"
G = Path("/var/tmp/pidfd-module-free-strings")
E.mkdir(parents=True, exist_ok=True)
G.mkdir(exist_ok=True)
bpf = r"""#include "reader.bpf.c"
struct ctl {unsigned long long pid,address,calls;int result;unsigned char output[3224];unsigned char scratch[4096];struct line_value line_value;};
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,struct ctl);} control SEC(".maps");
SEC("fentry.s/IOSEC_SYS_WRITE_PLACEHOLDER") int BPF_PROG(probe,const struct pt_regs *regs){unsigned int z=0;struct ctl *c=bpf_map_lookup_elem(&control,&z);if(!c||c->pid!=(bpf_get_current_pid_tgid()>>32))return 0;c->result=capture_state((struct source_event *)c->output,c->address,(char *)c->scratch,&c->line_value);c->calls++;return 0;}
"""
loader = r"""#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct ctl {uint64_t pid,address,calls;int result;unsigned char output[3224];unsigned char scratch[4096];unsigned char line_value[4104];};
struct frame {char file[128],function[64];int line,bytecode;};
struct event {uint64_t pid;unsigned int count,flags;struct frame frames[16];uint64_t birth;};
_Static_assert(sizeof(struct event)==3224,"ABI");
static void put64(void *p,int off,uint64_t x){memcpy((char*)p+off,&x,8);}
static void put32(void *p,int off,uint32_t x){memcpy((char*)p+off,&x,4);}
static unsigned char *str_obj(int length,int nul,int state,void **region){long page=sysconf(_SC_PAGESIZE);unsigned char *p=mmap(0,page*3,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)exit(7);if(mprotect(p+page*2,page,PROT_NONE))exit(8);unsigned char *s=p+page*2-(40+length+1);memset(s,0,40+length+1);put64(s,16,length);put32(s,32,state);memset(s+40,'a',length);if(nul>=0&&nul<length)s[40+nul]=0;*region=p;return s;}

static uint64_t pte(void *p){int f=open("/proc/self/pagemap",O_RDONLY);uint64_t v=0;long page=sysconf(_SC_PAGESIZE);if(f<0||pread(f,&v,8,((uintptr_t)p/page)*8)!=8)exit(20);close(f);return v>>63;}
static unsigned char *cold_split(const void *data,int n,int split,void **region){
 long page=sysconf(_SC_PAGESIZE);int f=memfd_create("iosec-partial-copy",MFD_CLOEXEC);if(f<0||ftruncate(f,2*page))exit(21);
 unsigned char *p=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_SHARED,f,0);close(f);if(p==MAP_FAILED)exit(22);
 unsigned char *at=p+page-split;memcpy(at,data,n);if(madvise(p+page,page,MADV_DONTNEED))exit(23);
 if(pte(p)!=1||pte(p+page)!=0){exit(24);}
 *region=p;return at;
}

int main(void){struct bpf_object *o=bpf_object__open_file("strings.bpf.o",NULL);if(libbpf_get_error(o))return 1;struct bpf_program *p; bpf_object__for_each_program(p,o) bpf_program__set_autoload(p,!strcmp(bpf_program__name(p),"probe"));if(bpf_object__load(o))return 1;struct bpf_link *l=bpf_program__attach(bpf_object__find_program_by_name(o,"probe"));if(libbpf_get_error(l))return 2;int fd=bpf_object__find_map_fd_by_name(o,"control"),sink=open("/dev/null",O_WRONLY);unsigned int z=0;
int lengths[]={0,1,3,7,62,63,64,126,127,128,512};int tests=0;
for(int side=0;side<2;side++)for(int k=0;k<11;k++)for(int embedded=0;embedded<2;embedded++){
 int len=lengths[k],cut=embedded&&len?len/2:-1;void *regions[2];unsigned char *file=str_obj(side==0?len:3,side==0?cut:-1,96,&regions[0]);unsigned char *name=str_obj(side==1?len:3,side==1?cut:-1,96,&regions[1]);
 unsigned char state[80]={0},frame[64]={0},code[144]={0},table[34]={0};put64(state,72,(uint64_t)frame);put64(frame,0,(uint64_t)code);put64(frame,56,(uint64_t)code+208);put64(code,8,11213488);put32(code,68,123);put64(code,112,(uint64_t)file);put64(code,120,(uint64_t)name);put64(code,136,(uint64_t)table);put64(table,16,2);table[32]=128;table[33]=0;
 struct ctl c={.pid=getpid(),.address=(uint64_t)state,.result=-999};memset(c.output,0x5a,3224);if(bpf_map_update_elem(fd,&z,&c,BPF_ANY)||write(sink,"x",1)!=1||bpf_map_lookup_elem(fd,&z,&c))return 3;
 struct event *e=(void*)c.output;struct frame expected={.line=123,.bytecode=0};int flen=side==0?len:3,nlen=side==1?len:3;if(cut>=0){if(side==0)flen=cut;else nlen=cut;}memset(expected.file,'a',flen<127?flen:127);memset(expected.function,'a',nlen<63?nlen:63);unsigned int flags=flen>=127||nlen>=63?16:0;
 if(c.calls!=1||c.result||e->count!=1||e->flags!=flags||memcmp(&e->frames[0],&expected,200)||!e->birth||(e->pid>>32)!=(uint64_t)getpid()) {fprintf(stderr,"FAIL side=%d len=%d cut=%d count=%u flags=%u expected=%u\n",side,len,cut,e->count,e->flags,flags);return 4;}
 for(int i=1;i<16;i++){struct frame zero={0};if(memcmp(&e->frames[i],&zero,200))return 5;}for(int i=0;i<2;i++)munmap(regions[i],sysconf(_SC_PAGESIZE)*3);tests++;
}
for(int mode=0;mode<11;mode++){
 void *regions[2];unsigned char *file=str_obj(3,-1,96,&regions[0]);unsigned char *name=str_obj(3,-1,96,&regions[1]);unsigned char state[80]={0},frame[64]={0},code[144]={0},table[34]={0};put64(state,72,(uint64_t)frame);put64(frame,0,(uint64_t)code);put64(frame,56,(uint64_t)code+208);put64(code,8,11213488);put32(code,68,123);put64(code,112,(uint64_t)file);put64(code,120,(uint64_t)name);put64(code,136,(uint64_t)table);put64(table,16,2);table[32]=128;table[33]=0;unsigned int expected=65;unsigned char *bad_state=state;
 switch(mode){case 0:put64(file,16,UINT64_MAX);break;case 1:put64(file,16,1048577);break;case 2:put32(file,32,0);expected=66;break;case 3:file[43]='a';break;case 4:put64(code,112,UINT64_MAX-8);break;case 5:put64(file,16,512);break;case 6:put64(code,8,0);expected=64;break;case 7:put64(code,112,0);break;case 8:put64(frame,0,(uint64_t)regions[0]+2*sysconf(_SC_PAGESIZE)-8);break;case 9:put64(code,136,(uint64_t)regions[0]+2*sysconf(_SC_PAGESIZE)-16);break;case 10:bad_state=(unsigned char*)regions[0]+2*sysconf(_SC_PAGESIZE)-72;break;}
 struct ctl c={.pid=getpid(),.address=(uint64_t)bad_state,.result=-999};if(bpf_map_update_elem(fd,&z,&c,BPF_ANY)||write(sink,"x",1)!=1||bpf_map_lookup_elem(fd,&z,&c))return 9;struct event *e=(void*)c.output;if(c.calls!=1||c.result||e->count||e->flags!=expected){fprintf(stderr,"MALFORMED_FAIL mode=%d count=%u flags=%u expected=%u\n",mode,e->count,e->flags,expected);return 10;}for(int i=0;i<2;i++)munmap(regions[i],sysconf(_SC_PAGESIZE)*3);
 }

for(int mode=0;mode<17;mode++){
 unsigned char state[80]={0},frame[64]={0},code[144]={0},table[40]={0},file[169]={0},name[48]={0};
 put64(file,16,mode==3?128:(mode==7?7:30));put32(file,32,96);memset(file+40,'a',mode==3?128:(mode==7?7:30));
 put64(name,16,mode==16?7:3);put32(name,32,96);memset(name+40,'a',mode==16?7:3);
 put64(code,8,11213488);put32(code,68,123);put64(code,112,(uint64_t)file);put64(code,120,(uint64_t)name);put64(code,136,(uint64_t)table);put64(table,16,2);table[32]=128;
 void *region=0;unsigned char *codeptr=code,*frameptr=frame,*stateptr=state;
 if(mode==1||mode==5)codeptr=cold_split(code,144,mode==5?12:72,&region);
 if(mode==6||mode==8){if(mode==8)put64(table,16,8);unsigned char *tableptr=cold_split(table,mode==8?40:34,mode==8?36:20,&region);put64(code,136,(uint64_t)tableptr);}
 if(mode==2||mode==3||mode==7){unsigned char *fileptr=cold_split(file,mode==3?169:(mode==7?48:71),mode==3?104:(mode==7?44:24),&region);put64(code,112,(uint64_t)fileptr);}
 if(mode==16){unsigned char *nameptr=cold_split(name,48,44,&region);put64(code,120,(uint64_t)nameptr);}
 put64(frame,0,(uint64_t)codeptr);put64(frame,56,(uint64_t)codeptr+208);
 if(mode==0)frameptr=cold_split(frame,64,32,&region);
 put64(state,72,(uint64_t)frameptr);
 if(mode==4|| (mode>=9&&mode<=15))stateptr=cold_split(state,80,mode==4?76:72+mode-8,&region);
 struct ctl c={.pid=getpid(),.address=(uint64_t)stateptr,.result=-999};
 if(bpf_map_update_elem(fd,&z,&c,BPF_ANY)||write(sink,"x",1)!=1||bpf_map_lookup_elem(fd,&z,&c))return 25;
 struct event *e=(void*)c.output;struct frame expected={.line=123,.bytecode=0};memset(expected.file,'a',mode==3?127:(mode==7?7:30));memset(expected.function,'a',mode==16?7:3);
 if(c.calls!=1||c.result||e->count!=1||e->flags!=(mode==3?16:0)||memcmp(&e->frames[0],&expected,200))return 26;
 if(pte((unsigned char*)region+sysconf(_SC_PAGESIZE))!=1)return 27;
 printf("PARTIAL_COLD_CASE mode=%d before=0 after=1 flags=%u\n",mode,e->flags);
 munmap(region,2*sysconf(_SC_PAGESIZE));
}
 printf("STRING_GUARD_CASES %d MALFORMED_CASES 11\n",tests);close(sink);bpf_link__destroy(l);bpf_object__close(o);return 0;}
"""
bpf = bpf.replace(
    "IOSEC_SYS_WRITE_PLACEHOLDER",
    "__x64_sys_write" if __import__("settings").ARCH == "x86" else "__arm64_sys_write",
)
config = (__import__("settings").PREPARED / "config.h").read_text()
import re

address = re.search(r"^#define CODE_TYPE_ADDRESS (\d+)$", config, re.M)[1]
offsets = {
    key: int(value) for key, value in re.findall(r"^#define (\w+) (\d+)$", config, re.M)
}
# Keep the guard-page controls meaningful for each real interpreter layout.
loader = loader.replace("put64(code,8,11213488)", "put64(code,8,synthetic_code_type())")
loader = loader.replace("#include <stdint.h>", "#include <stdint.h>\n#include <link.h>")
type_helper = """static int main_text(struct dl_phdr_info *info,size_t size,void *out){
 (void)size;if(info->dlpi_name[0])return 0;uint64_t start=UINT64_MAX;
 for(unsigned int i=0;i<info->dlpi_phnum;i++){const ElfW(Phdr) *p=&info->dlpi_phdr[i];if(p->p_type==PT_LOAD&&(p->p_flags&PF_X)&&p->p_vaddr<start)start=p->p_vaddr;}
 *(uint64_t*)out=info->dlpi_addr+start;return 1;}
static uint64_t synthetic_code_type(void){uint64_t start=0;dl_iterate_phdr(main_text,&start);return start-PYTHON_TEXT_ADDRESS+CODE_TYPE_ADDRESS;}
"""
type_helper = type_helper.replace(
    "PYTHON_TEXT_ADDRESS", str(offsets["PYTHON_TEXT_ADDRESS"])
).replace("CODE_TYPE_ADDRESS", address)
loader = loader.replace("static uint64_t pte", type_helper + "static uint64_t pte")
for literal, macro in [
    (72, "TSTATE_FRAME"),
    (56, "FRAME_INSTR"),
    (68, "CODE_FIRSTLINE"),
    (112, "CODE_FILENAME"),
    (120, "CODE_NAME"),
    (136, "CODE_LINETABLE"),
]:
    loader = loader.replace(f",{literal},", f",{offsets[macro]},")
loader = loader.replace("+208", f'+{offsets["CODE_BYTECODE"]}')
state_size = offsets["TSTATE_FRAME"] + 8
frame_size = max(
    offsets[k] + 8 for k in ("FRAME_CODE", "FRAME_PREVIOUS", "FRAME_INSTR")
)
if offsets["PYTHON_MINOR"] >= 11:
    frame_size = max(frame_size, ((offsets["FRAME_OWNER"] + 8) // 8) * 8)
code_size = max(
    offsets[k] + 8 for k in ("CODE_FILENAME", "CODE_NAME", "CODE_LINETABLE")
)
loader = (
    loader.replace("state[80]", f"state[{state_size}]")
    .replace("frame[64]", f"frame[{frame_size}]")
    .replace("code[144]", f"code[{code_size}]")
)
loader = loader.replace(
    "cold_split(state,80,mode==4?76:72+mode-8",
    f'cold_split(state,{state_size},mode==4?{offsets["TSTATE_FRAME"]+4}:{offsets["TSTATE_FRAME"]}+mode-8',
)
loader = loader.replace(
    "cold_split(frame,64,32", f"cold_split(frame,{frame_size},{frame_size//2}"
)
loader = loader.replace(
    "cold_split(code,144,mode==5?12:72",
    f"cold_split(code,{code_size},mode==5?12:{code_size//2}",
)
loader = loader.replace("-72;", f'-{offsets["TSTATE_FRAME"]};')
if offsets["FRAME_CODE"]:
    loader = loader.replace("put64(frame,0,", f'put64(frame,{offsets["FRAME_CODE"]},')
if offsets["PYTHON_MINOR"] == 10:
    loader = re.sub(
        r"put64\(frame,"
        + str(offsets["FRAME_INSTR"])
        + r",\(uint64_t\)code(ptr)?\+"
        + str(offsets["CODE_BYTECODE"])
        + r"\)",
        f'put32(frame,{offsets["FRAME_INSTR"]},0)',
        loader,
    )
    loader = loader.replace("table[32]=128", "table[32]=2")
if offsets["ASCII_DATA"] != 40:
    data = offsets["ASCII_DATA"]
    extra = data - 40
    loader = loader.replace("40+length+1", f"{data}+length+1")
    for obj in ("s", "file", "name"):
        loader = loader.replace(obj + "+40", obj + "+" + str(data))
    loader = loader.replace("s[40+", f"s[{data}+")
    loader = loader.replace("file[43]", f"file[{data+3}]")
    loader = loader.replace("file[169]", f"file[{169+extra}]").replace(
        "name[48]", f"name[{48+extra}]"
    )
    loader = loader.replace(
        "mode==3?169:(mode==7?48:71),mode==3?104:(mode==7?44:24)",
        f"mode==3?{169+extra}:(mode==7?{48+extra}:{71+extra}),mode==3?{104+extra}:(mode==7?{44+extra}:24)",
    )
    loader = loader.replace(
        "cold_split(name,48,44", f"cold_split(name,{48+extra},{44+extra}"
    )
if offsets["TSTATE_FRAME_INDIRECT"]:
    helper = f"static unsigned char synthetic_cframe[{offsets['CFRAME_FRAME']+8}];\nstatic void put_root(void *state,uint64_t frame){{put64(synthetic_cframe,{offsets['CFRAME_FRAME']},frame);put64(state,{offsets['TSTATE_FRAME']},(uint64_t)synthetic_cframe);}}\n"
    loader = loader.replace("static uint64_t pte", helper + "static uint64_t pte")
    loader = loader.replace(
        f'put64(state,{offsets["TSTATE_FRAME"]},', "put_root(state,"
    )
    # The helper itself must retain its direct pointer store.
    loader = loader.replace(
        "put_root(state,(uint64_t)synthetic_cframe)",
        f'put64(state,{offsets["TSTATE_FRAME"]},(uint64_t)synthetic_cframe)',
    )
(G / "strings.bpf.c").write_text(bpf)
(G / "loader.c").write_text(loader)
for n in [
    "reader.bpf.c",
    "vmlinux.h",
    "config.h",
    "kernel_layout.h",
    "python_layout.h",
    "arch.h",
]:
    shutil.copy2(R / "evidence/build" / n, G / n)
for i, cmd in enumerate(
    [
        [
            "clang",
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-mcpu=v3",
            *__import__("settings").BPF_INCLUDES,
            "-D__TARGET_ARCH_" + __import__("settings").ARCH,
            "-I.",
            "-c",
            "strings.bpf.c",
            "-o",
            "strings.bpf.o",
        ],
        [
            "gcc",
            "-O2",
            "-Wall",
            "-Werror",
            *__import__("settings").BPF_INCLUDES,
            "loader.c",
            *__import__("settings").BPF_LIBS,
            "-o",
            "loader",
        ],
        ["./loader"],
    ]
):
    p = subprocess.run(cmd, cwd=G, capture_output=True, text=True, timeout=120)
    (E / f"step-{i}.log").write_text(p.stdout + p.stderr)
    assert p.returncode == 0, p.stderr[-2000:]
    print(p.stdout, end="")
for n in ["strings.bpf.c", "strings.bpf.o", "loader.c", "loader", "vmlinux.h"]:
    shutil.copy2(G / n, E / n)
report = dict(
    passed=True,
    real_kernel_capture=True,
    owned_synthetic_metadata=True,
    guard_page_cases=44,
    malformed_cases=11,
    partial_cold_cases=17,
    checks=[
        "Exact200byte frame including zero tails",
        "Short/exact-limit/over-limit filename and function",
        "Embedded NUL and empty strings",
        "Both string objects end immediately before PROT_NONE page",
        "All15unused frames zero",
        "Unmapped eight-byte rootframe/code-type/linetable-length reads return explicit error flags65",
        "Exactly8B file/function payloads and linetable bytes recover across cold page",
        "Root frame-pointer reads at all seven unaligned cross-page splits recover exact frames",
        "Frame/code/Unicode-header/string and eight-byte tstate-frame/code-type/linetable-length reads straddle resident then absent PTE; full output recovered and cold PTE faulted in",
    ],
    backend="module-free",
    artifacts={
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in E.iterdir()
        if p.is_file() and p.name != "verification.json"
    },
    full_goal_complete=False,
)
(E / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
