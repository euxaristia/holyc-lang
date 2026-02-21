I64 SumIntArgs(
  I64 p0,  I64 p1,  I64 p2,  I64 p3,  I64 p4,
  I64 p5,  I64 p6,  I64 p7,  I64 p8,  I64 p9,
  I64 p10, I64 p11, I64 p12, I64 p13, I64 p14,
  I64 p15, I64 p16, I64 p17, I64 p18, I64 p19)
{
  return p0 + p7 + p8 + p19;
}

F64 SumFloatArgs(
  F64 p0,  F64 p1,  F64 p2,  F64 p3,  F64 p4,
  F64 p5,  F64 p6,  F64 p7,  F64 p8,  F64 p9,
  F64 p10, F64 p11, F64 p12, F64 p13, F64 p14,
  F64 p15, F64 p16, F64 p17, F64 p18, F64 p19)
{
  return p0 + p7 + p8 + p19;
}

I32 Main()
{
  I64 (*int_fn)(
    I64, I64, I64, I64, I64,
    I64, I64, I64, I64, I64,
    I64, I64, I64, I64, I64,
    I64, I64, I64, I64, I64) = &SumIntArgs;

  F64 (*float_fn)(
    F64, F64, F64, F64, F64,
    F64, F64, F64, F64, F64,
    F64, F64, F64, F64, F64,
    F64, F64, F64, F64, F64) = &SumFloatArgs;

  I64 iret = int_fn(
      0, 1, 2, 3, 4,
      5, 6, 7, 8, 9,
      10, 11, 12, 13, 14,
      15, 16, 17, 18, 19);
  F64 fret = float_fn(
      0.0, 1.0, 2.0, 3.0, 4.0,
      5.0, 6.0, 7.0, 8.0, 9.0,
      10.0, 11.0, 12.0, 13.0, 14.0,
      15.0, 16.0, 17.0, 18.0, 19.0);

  if (iret != 34) return 1;
  if (fret != 34.0) return 2;
  return 0;
}
