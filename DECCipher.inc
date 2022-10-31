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

{$ifndef DECCIPHER_HEADING}
{$define DECCIPHER_HEADING}

//------------------------------------------------------------------------------

function IDEAMul(X,Y: LongWord): LongWord;
begin
  X := Word(X);
  Y := Word(Y);
  if (X <> 0) and (Y <> 0) then
  begin
    //Result := (X * Y) mod $10001;
    // Ugly but up to 30 cycles faster under -O2
    X := X * Y;
    Result := X - (X shr 16);
    if Word(X) < Word(Result) then
      Inc(Result);
  end
  else
    Result := 1 - X - Y;
end;


{$else}    // DECCIPHER_HEADING
//------------------------------------------------------------------------------
procedure TCipher_Blowfish.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I,A,B: LongWord;
  P: PLongArray;
  D: PBlowfish;
begin
  Assert(Size = Context.BlockSize);

  D := FUser;
  P := Pointer(PAnsiChar(FUser) + SizeOf(Blowfish_Data));
  A := {$IFNDEF ENDIAN_BIG}SwapLong(PLongArray(Source)[0]){$ELSE}PLongArray(Source)[0]{$ENDIF} xor P[0];
  P := @P[1];
  B := {$IFNDEF ENDIAN_BIG}SwapLong(PLongArray(Source)[1]){$ELSE}PLongArray(Source)[1]{$ENDIF};
  for I := 0 to 7 do
  begin
    B := B xor P[0] xor (D[0, A shr 24        ] +
                         D[1, A shr 16 and $FF] xor
                         D[2, A shr  8 and $FF] +
                         D[3, A        and $FF]);

    A := A xor P[1] xor (D[0, B shr 24        ] +
                         D[1, B shr 16 and $FF] xor
                         D[2, B shr  8 and $FF] +
                         D[3, B        and $FF]);
    P := @P[2];
  end;
  PLongArray(Dest)[0] := {$IFNDEF ENDIAN_BIG}SwapLong(B xor P[0]){$ELSE}B xor P[0]{$ENDIF};
  PLongArray(Dest)[1] := {$IFNDEF ENDIAN_BIG}SwapLong(A){$ELSE}A{$ENDIF};
end;

procedure TCipher_Blowfish.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I,A,B: LongWord;
  P: PLongArray;
  D: PBlowfish;
begin
  Assert(Size = Context.BlockSize);

  D := FUser;
  P := Pointer(PAnsiChar(FUser) + SizeOf(Blowfish_Data) + SizeOf(Blowfish_Key) - SizeOf(Integer));
  A := {$IFNDEF ENDIAN_BIG}SwapLong(PLongArray(Source)[0]){$ELSE}PLongArray(Source)[0]{$ENDIF} xor P[0];
  B := {$IFNDEF ENDIAN_BIG}SwapLong(PLongArray(Source)[1]){$ELSE}PLongArray(Source)[1]{$ENDIF};
  for I := 0 to 7 do
  begin
    Dec(PLongWord(P), 2);
    B := B xor P[1] xor (D[0, A shr 24        ] +
                         D[1, A shr 16 and $FF] xor
                         D[2, A shr  8 and $FF] +
                         D[3, A        and $FF]);
    A := A xor P[0] xor (D[0, B shr 24        ] +
                         D[1, B shr 16 and $FF] xor
                         D[2, B shr  8 and $FF] +
                         D[3, B        and $FF]);
  end;
  Dec(PLongWord(P));
  PLongArray(Dest)[0] := {$IFNDEF ENDIAN_BIG}SwapLong(B xor P[0]){$ELSE}B xor P[0]{$ENDIF};
  PLongArray(Dest)[1] := {$IFNDEF ENDIAN_BIG}SwapLong(A){$ELSE}A{$ENDIF};
end;



//------------------------------------------------------------------------------
procedure TCipher_Q128.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  D: PLongArray;
  B0,B1,B2,B3,I: LongWord;
begin
  Assert(Size = Context.BufferSize);

  D  := FUser;
  B0 := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[0]{$ELSE}SwapLong(PLongArray(Source)[0]){$ENDIF};
  B1 := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[1]{$ELSE}SwapLong(PLongArray(Source)[1]){$ENDIF};
  B2 := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[2]{$ELSE}SwapLong(PLongArray(Source)[2]){$ENDIF};
  B3 := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[3]{$ELSE}SwapLong(PLongArray(Source)[3]){$ENDIF};
  for I := 0 to 15 do
  begin
    B1 := B1 xor (Q128_Data[B0 and $03FF] + D[0]); B0 := B0 shl 10 or B0 shr 22;
    B2 := B2 xor (Q128_Data[B1 and $03FF] + D[1]); B1 := B1 shl 10 or B1 shr 22;
    B3 := B3 xor (Q128_Data[B2 and $03FF] + D[2]); B2 := B2 shl 10 or B2 shr 22;
    B0 := B0 xor (Q128_Data[B3 and $03FF] + D[3]); B3 := B3 shl 10 or B3 shr 22;
    D := @D[4];
  end;
  PLongArray(Dest)[0] := {$IFNDEF ENDIAN_BIG}B0{$ELSE}SwapLong(B0){$ENDIF};
  PLongArray(Dest)[1] := {$IFNDEF ENDIAN_BIG}B1{$ELSE}SwapLong(B1){$ENDIF};
  PLongArray(Dest)[2] := {$IFNDEF ENDIAN_BIG}B2{$ELSE}SwapLong(B2){$ENDIF};
  PLongArray(Dest)[3] := {$IFNDEF ENDIAN_BIG}B3{$ELSE}SwapLong(B3){$ENDIF};
end;



//------------------------------------------------------------------------------

procedure TCipher_RC6.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  K: PLongArray;
  I,T,U,A,B,C,D: LongWord;
begin
  Assert(Size = Context.BlockSize);

  K := FUser;
  A := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[0]{$ELSE}SwapLong(PLongArray(Source)[0]){$ENDIF};
  B := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[1]{$ELSE}SwapLong(PLongArray(Source)[1]){$ENDIF} + K[0];
  C := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[2]{$ELSE}SwapLong(PLongArray(Source)[2]){$ENDIF};
  D := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[3]{$ELSE}SwapLong(PLongArray(Source)[3]){$ENDIF} + K[1];
  for I := 1 to FRounds do
  begin
    K := @K[2];
    T := B * (B + B +1);
    T := T shl 5 or T shr 27;
    U := D * (D + D +1);
    U := U shl 5 or U shr 27;
    A := A xor T;
    A := A shl (U and 31) or A shr ((32 - U) and 31) + K[0];
    C := C xor U;
    C := C shl (T and 31) or C shr ((32 - T) and 31) + K[1];
    T := A; A := B; B := C; C := D; D := T;
  end;
  PLongArray(Dest)[0] := A + K[2];
  PLongArray(Dest)[1] := B;
  PLongArray(Dest)[2] := C + K[3];
  PLongArray(Dest)[3] := D;
  {$IFDEF ENDIAN_BIG}
  SwapLongBuffer(Dest^, Dest^, 4);
  {$ENDIF}
end;


procedure TCipher_RC6.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I,U,T,A,B,C,D: LongWord;
  K: PLongArray;
begin
  Assert(Size = Context.BlockSize);

  K := @PLongArray(FUser)[FRounds * 2];
  A := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[0]{$ELSE}SwapLong(PLongArray(Source)[0]){$ENDIF} - K[2];
  B := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[1]{$ELSE}SwapLong(PLongArray(Source)[1]){$ENDIF};
  C := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[2]{$ELSE}SwapLong(PLongArray(Source)[2]){$ENDIF} - K[3];
  D := {$IFNDEF ENDIAN_BIG}PLongArray(Source)[3]{$ELSE}SwapLong(PLongArray(Source)[3]){$ENDIF};
  for I := 1 to FRounds do
  begin
    T := A; A := D; D := C; C := B; B := T;
    U := D * (D + D +1);
    U := U shl 5 or U shr 27;
    T := B * (B + B +1);
    T := T shl 5 or T shr 27;
    C := C - K[1];
    C := C shr (T and 31) or C shl ((32 - T) and 31) xor U;
    A := A - K[0];
    A := A shr (U and 31) or A shl ((32 - U) and 31) xor T;
    Dec(PLongWord(K), 2);
  end;
  PLongArray(Dest)[0] := A;
  PLongArray(Dest)[1] := B - K[0];
  PLongArray(Dest)[2] := C;
  PLongArray(Dest)[3] := D - K[1];
  {$IFDEF ENDIAN_BIG}
  SwapLongBuffer(Dest^, Dest^, 4);
  {$ENDIF}
end;

{$endif}

