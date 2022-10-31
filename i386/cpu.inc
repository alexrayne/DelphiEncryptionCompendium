{*****************************************************************************

  Delphi Encryption Compendium (DEC Part I)
  Version 5.3 for Delphi 7 - 10.4 or higher/FPC 2.6 or higher

  Remarks:          Freeware, Copyright must be included

  Original Author:  (c) 2006 Hagen Reddmann, HaReddmann [at] T-Online [dot] de
  Modifications:    (c) 2008 Arvid Winkelsdorf, info [at] digivendo [dot] de
                    (c) 2017, 2021 decfpc
                    (c) 2022 alexrain

 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*****************************************************************************}

{$ASMMODE intel}


{check is CPUID Instruction present}
function CPUID_Found: LongBool; assembler;
asm
       PUSHFD
       PUSHFD
       POP     EAX
       MOV     EDX,EAX
       XOR     EAX,0040000h
       PUSH    EAX
       POPFD
       PUSHFD
       POP     EAX
       XOR     EAX,EDX
       JZ      @@1
       PUSHFD
       POP     EAX
       MOV     EDX,EAX
       XOR     EAX,0200000h
       PUSH    EAX
       POPFD
       PUSHFD
       POP     EAX
       XOR     EAX,EDX
@@1:   POPFD
end;


{initialize the CPU Datastruct}
procedure GetCPU;

  function CRC(const Value): Cardinal; assembler;
  asm
      MOV  EDX,EAX
      MOV  EAX,[EDX + 0]
      XOR  EAX,[EDX + 4]
      XOR  EAX,[EDX + 8]
  end;

var
  ID: Word;
begin
  FillChar(FCPU, SizeOf(FCPU), 0);
  if CPUID_Found then
  asm
       PUSH    EDI
       PUSH    EBX

       MOV     EDI,OFFSET FCPU
       LEA     EDI,[EDI].TCPUData.Vendor
       XOR     EAX,EAX
       DW      0A20Fh             //     CPUID
       MOV     [EDI + 0],EBX
       MOV     [EDI + 4],EDX
       MOV     [EDI + 8],ECX

       MOV     EDI,OFFSET FCPU
       CMP     EAX,2
       JL      @@1
       MOV     EAX,2
       DW      0A20Fh
       MOV     [EDI].TCPUData.TLB_EAX,EAX
       MOV     [EDI].TCPUData.TLB_EDX,EDX
       MOV     [EDI].TCPUData.TLB_EBX,EBX
       MOV     [EDI].TCPUData.TLB_ECX,ECX
@@1:   MOV     EAX,1
       XOR     EBX,EBX
       XOR     ECX,ECX
       DW      0A20Fh
       MOV     [EDI].TCPUData.Signature,EAX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[0],EAX
       MOV     [EDI].TCPUData.Features_EDX,EDX
       MOV     [EDI].TCPUData.Features_EBX,EBX
       MOV     [EDI].TCPUData.Features_ECX,ECX

       MOV     EDX,EAX
       AND     EAX,0Fh
       MOV     [EDI].TCPUData.Stepping,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [EDI].TCPUData.Model,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [EDI].TCPUData.Family,AL
       SHR     EDX,4
       AND     EDX,0Fh
       MOV     [EDI].TCPUData.Typ,DL

       MOV     EAX,080000000h
       XOR     EDX,EDX
       XOR     EAX,EAX
       DW      0A20Fh
       TEST    EAX,EAX
       JLE     @@3
       AND     EDX,EDX
       JZ      @@3
       PUSH    EAX
       MOV     EAX,080000001h
       DW      0A20Fh
       MOV     [EDI].TCPUData.FeaturesEx_EDX,EDX
       MOV     [EDI].TCPUData.FeaturesEx_EBX,EBX
       MOV     [EDI].TCPUData.FeaturesEx_ECX,ECX
       POP     EAX
       CMP     EAX,1
       JBE     @@3
       PUSH    ESI
       PUSH    EDI
       XOR     ESI,ESI
       LEA     EDI,[EDI].TCPUData.VendorEx
@@2:   LEA     EAX,[080000002h + ESI]
       XOR     EDX,EDX
       XOR     EBX,EBX
       XOR     ECX,ECX
       DW      0A20Fh
       MOV     [EDI +  0],EAX
       MOV     [EDI +  4],EBX
       MOV     [EDI +  8],ECX
       MOV     [EDI + 12],EDX
       INC     ESI
       ADD     EDI,16
       AND     ESI,3
       JNZ     @@2
       POP     EDI
       POP     ESI

@@3:   XOR     EDX,EDX
       XOR     ECX,ECX
       XOR     EBX,EBX
       MOV     EAX,3
       DW      0A20Fh
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[ 4],EDX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[ 8],ECX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[12],EBX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[16],EAX
       POP     EBX
       POP     EDI
  end else
  try
    FCPU.Family := cf386;
    asm
       XADD    EAX,EAX
       BSWAP   EAX

       PUSH    EDI
       MOV     EDI,OFFSET FCPU
       MOV     [EDI].TCPUData.Family,cf486
       MOV     EAX,CR0
       AND     EAX,not 010h
       MOV     CR0,EAX
       MOV     EAX,CR0
       AND     EAX,    010h
       JZ      @@1
       INC     [EDI].TCPUData.Model
       OR      ID,1
       FNINIT
       FNSTSW  ID
       CMP     ID[0],0
       JNE     @@1
       FNSTCW  ID
       MOV     AX,ID
       AND     AX,013Fh
       CMP     AX,003Fh
       JNE     @@1
       INC     [EDI].TCPUData.Model
@@1:   POP     EDI
    end;
  except
  end;
  FCPU.VendorID := CRC(FCPU.Vendor);
end;

