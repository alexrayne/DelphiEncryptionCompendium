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

{$ifndef DECCIPHER_HEADING}
{$define DECCIPHER_HEADING}

function IDEAMul(X,Y: LongWord): LongWord;
asm
       AND    EAX,0FFFFh
       JZ     @@1
       AND    EDX,0FFFFh
       JZ     @@1
       MUL    EDX
       MOV    EDX,EAX
       MOV    ECX,EAX
       SHR    EDX,16
       SUB    EAX,EDX
       SUB    CX,AX
       ADC    EAX,0
       RET
@@1:   LEA    EAX,[EAX + EDX -1]
       NEG    EAX
end;

//------------------------------------------------------------------------------


{$else}    // DECCIPHER_HEADING


procedure TCipher_Blowfish.DoEncode(Source, Dest: Pointer; Size: Integer);
// specialy for CPU >= 486
// Source = EDX, Dest=ECX, Size on Stack
asm
        PUSH   EDI
        PUSH   ESI
        PUSH   EBX
        PUSH   EBP
        PUSH   ECX
        MOV    ESI,[EAX].TCipher_Blowfish.FUser
        MOV    EBX,[EDX + 0]     // A
        MOV    EBP,[EDX + 4]     // B
        BSWAP  EBX               // CPU >= 486
        BSWAP  EBP
        XOR    EBX,[ESI + 4 * 256 * 4]
        XOR    EDI,EDI
@@1:    MOV    EAX,EBX
        SHR    EBX,16
        MOVZX  ECX,BH
        AND    EBX,0FFh
        MOV    ECX,[ESI + ECX * 4 + 1024 * 0]
        MOV    EBX,[ESI + EBX * 4 + 1024 * 1]
        MOVZX  EDX,AH
        ADD    EBX,ECX
        MOVZX  ECX,AL
        MOV    EDX,[ESI + EDX * 4 + 1024 * 2]
        MOV    ECX,[ESI + ECX * 4 + 1024 * 3]
        XOR    EBX,EDX
        XOR    EBP,[ESI + 4 * 256 * 4 + 4 + EDI * 4]
        ADD    EBX,ECX
        INC    EDI
        XOR    EBX,EBP
        TEST   EDI,010h
        MOV    EBP,EAX
        JZ     @@1
        POP    EAX
        XOR    EBP,[ESI + 4 * 256 * 4 + 17 * 4]
        BSWAP  EBX
        BSWAP  EBP
        MOV    [EAX + 4],EBX
        MOV    [EAX + 0],EBP
        POP    EBP
        POP    EBX
        POP    ESI
        POP    EDI
end;

procedure TCipher_Blowfish.DoDecode(Source, Dest: Pointer; Size: Integer);
asm
        PUSH   EDI
        PUSH   ESI
        PUSH   EBX
        PUSH   EBP
        PUSH   ECX
        MOV    ESI,[EAX].TCipher_Blowfish.FUser
        MOV    EBX,[EDX + 0]     // A
        MOV    EBP,[EDX + 4]     // B
        BSWAP  EBX
        BSWAP  EBP
        XOR    EBX,[ESI + 4 * 256 * 4 + 17 * 4]
        MOV    EDI,16
@@1:    MOV    EAX,EBX
        SHR    EBX,16
        MOVZX  ECX,BH
        MOVZX  EDX,BL
        MOV    EBX,[ESI + ECX * 4 + 1024 * 0]
        MOV    EDX,[ESI + EDX * 4 + 1024 * 1]
        MOVZX  ECX,AH
        LEA    EBX,[EBX + EDX]
        MOVZX  EDX,AL
        MOV    ECX,[ESI + ECX * 4 + 1024 * 2]
        MOV    EDX,[ESI + EDX * 4 + 1024 * 3]
        XOR    EBX,ECX
        XOR    EBP,[ESI + 4 * 256 * 4 + EDI * 4]
        LEA    EBX,[EBX + EDX]
        XOR    EBX,EBP
        DEC    EDI
        MOV    EBP,EAX
        JNZ    @@1
        POP    EAX
        XOR    EBP,[ESI + 4 * 256 * 4]
        BSWAP  EBX
        BSWAP  EBP
        MOV    [EAX + 0],EBP
        MOV    [EAX + 4],EBX
        POP    EBP
        POP    EBX
        POP    ESI
        POP    EDI
end;



//------------------------------------------------------------------------------
procedure TCipher_RC6.DoEncode(Source, Dest: Pointer; Size: Integer);
asm
      PUSH  EBX
      PUSH  ESI
      PUSH  EDI
      PUSH  EBP
      PUSH  ECX
      MOV   EBP,[EAX].TCipher_RC6.FRounds  // Rounds
      MOV   ESI,[EAX].TCipher_RC6.FUser    // Key
      MOV   EAX,[EDX +  0]   // A
      MOV   EBX,[EDX +  4]   // B
      MOV   EDI,[EDX +  8]   // C
      MOV   EDX,[EDX + 12]   // D
      ADD   EBX,[ESI + 0]    // Inc(B, K[0])
      ADD   EDX,[ESI + 4]    // Inc(D, K[1])
      ADD   ESI,8            // Inc(PInteger(K), 2)
@@1:  LEA   ECX,[EBX * 2 +1] // ECX := B * 2 +1
      IMUL  ECX,EBX          // ECX := ECX * B
      ROL   ECX,5            // T := ROL(B * (B * 2 +1), 5)
      PUSH  ECX              // save T
      XOR   EAX,ECX          // A := A xor T
      LEA   ECX,[EDX * 2 +1] // ECX := D * 2 +1
      IMUL  ECX,EDX          // ECX := ECX * D
      ROL   ECX,5            // U := ROL(D * (D * 2 +1), 5)
      XOR   EDI,ECX          // C := C xor U
      ROL   EAX,CL           // A := ROL(A xor T, U)
      POP   ECX              // restore T
      ADD   EAX,[ESI + 0]    // Inc(A, K[0])
      ROL   EDI,CL           // C := ROL(C xor U, T)
      MOV   ECX,EAX          // T := A
      ADD   EDI,[ESI + 4]    // Inc(C, K[1])
      MOV   EAX,EBX          // A := B
      MOV   EBX,EDI          // B := C
      MOV   EDI,EDX          // C := D
      DEC   EBP
      MOV   EDX,ECX          // D := T;
      LEA   ESI,[ESI + 8]    // Inc(PInteger(K), 2)
      JNZ   @@1
      ADD   EAX,[ESI + 0]    // Inc(A, K[0])
      ADD   EDI,[ESI + 4]    // Inc(C, K[1])
      POP   ECX
      MOV   [ECX +  0],EAX   // A
      MOV   [ECX +  4],EBX   // B
      MOV   [ECX +  8],EDI   // C
      MOV   [ECX + 12],EDX   // D
      POP   EBP
      POP   EDI
      POP   ESI
      POP   EBX
end;


procedure TCipher_RC6.DoDecode(Source, Dest: Pointer; Size: Integer);
asm
      PUSH  EBX
      PUSH  ESI
      PUSH  EDI
      PUSH  EBP
      PUSH  ECX
      MOV   EBP,[EAX].TCipher_RC6.FRounds  // Rounds
      MOV   ESI,[EAX].TCipher_RC6.FUser    // Key
      LEA   ESI,[ESI + EBP * 8]            // Key[FRounds * 2]
      MOV   EAX,[EDX +  0]   // A
      MOV   EBX,[EDX +  4]   // B
      MOV   EDI,[EDX +  8]   // C
      MOV   EDX,[EDX + 12]   // D
      SUB   EDI,[ESI + 12]   // Dec(C, K[3])
      SUB   EAX,[ESI +  8]   // Dec(A, K[2])
@@1:  MOV   ECX,EAX          // T := A
      SUB   EDX,[ESI + 0]    // Dec(A, K[0])
      MOV   EAX,EDX          // A := D
      MOV   EDX,EDI          // D := C
      SUB   EBX,[ESI + 4]    // Dec(C, K[1])
      MOV   EDI,EBX          // C := B
      MOV   EBX,ECX          // B := T;
      LEA   ECX,[EDX * 2 +1] // ECX := D * 2 +1
      IMUL  ECX,EDX          // ECX := ECX * D
      ROL   ECX,5            // U := ROL(D * (D * 2 +1), 5)
      PUSH  ECX              // save U
      ROR   EAX,CL           // A := ROR(A - K[0], U)
      LEA   ECX,[EBX * 2 +1] // ECX := B * 2 +1
      IMUL  ECX,EBX          // ECX := ECX * B
      ROL   ECX,5            // T := ROL(B * (B * 2 +1), 5)
      XOR   EAX,ECX          // A := A xor T
      ROR   EDI,CL           // C := ROR(C - K[1], T)
      POP   ECX              // restore U
      XOR   EDI,ECX          // C := C xor U
      DEC   EBP
      LEA   ESI,[ESI - 8]    // Dec(PInteger(K), 2)
      JNZ   @@1
      SUB   EBX,[ESI + 0]    // Dec(B, K[0])
      SUB   EDX,[ESI + 4]    // Inc(D, K[1])
      POP   ECX
      MOV   [ECX +  0],EAX   // A
      MOV   [ECX +  4],EBX   // B
      MOV   [ECX +  8],EDI   // C
      MOV   [ECX + 12],EDX   // D
      POP   EBP
      POP   EDI
      POP   ESI
      POP   EBX
end;



//------------------------------------------------------------------------------
procedure TCipher_Q128.DoDecode(Source, Dest: Pointer; Size: Integer);
asm
       PUSH   ESI
       PUSH   EDI
       PUSH   EBX
       PUSH   EBP
       PUSH   ECX
       MOV    EDI,[EAX].TCipher_Q128.FUser
       LEA    EDI,[EDI + 64 * 4]
       MOV    ESI,[EDX +  0]   // B0
       MOV    EBX,[EDX +  4]  // B1
       MOV    ECX,[EDX +  8]  // B2
       MOV    EDX,[EDX + 12]  // B3
       MOV    EBP,16
@@1:   SUB    EDI,16
       ROR    EDX,10
       MOV    EAX,EDX
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI + 12]
       XOR    ESI,EAX
       ROR    ECX,10
       MOV    EAX,ECX
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI +  8]
       XOR    EDX,EAX
       ROR    EBX,10
       MOV    EAX,EBX
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI +  4]
       XOR    ECX,EAX
       ROR    ESI,10
       MOV    EAX,ESI
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI]
       XOR    EBX,EAX
       DEC    EBP
       JNZ    @@1
       POP    EAX
       MOV    [EAX +  0],ESI  // B0
       MOV    [EAX +  4],EBX  // B1
       MOV    [EAX +  8],ECX  // B2
       MOV    [EAX + 12],EDX  // B3
       POP    EBP
       POP    EBX
       POP    EDI
       POP    ESI
end;

{$endif}



