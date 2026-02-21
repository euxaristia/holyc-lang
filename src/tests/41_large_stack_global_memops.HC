I8 g_i8;
I16 g_i16;
I32 g_i32;
I64 g_i64;
F64 g_f64;
U8 *g_ptr;

I64 TouchLargeStackAndGlobals()
{
  I64 pad[900];
  I64 *tail;
  I32 *g_i32_ptr;

  pad[0] = 11;
  pad[700] = 22;
  pad[899] = 33;
  tail = &pad[899];

  g_i8 = 4;
  g_i16 = 5;
  g_i32 = 6;
  g_i64 = 7;
  g_f64 = 8.0;
  g_ptr = "ok";

  g_i32_ptr = &g_i32;
  *g_i32_ptr = *g_i32_ptr + 10;

  if (pad[0] != 11) return 1;
  if (pad[700] != 22) return 2;
  if (*tail != 33) return 3;
  if (g_ptr[0] != 'o') return 4;
  if (g_i32 != 16) return 5;

  return g_i8 + g_i16 + g_i32 + g_i64;
}

I32 Main()
{
  return TouchLargeStackAndGlobals() != 32;
}
