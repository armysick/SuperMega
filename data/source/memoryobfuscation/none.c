void memoryobfuscation(){
  FILE* f = fopen('C:\\something.txt', 'wb');
  fwrite("HELLO!123\n", 1, f);
  fclose(f);
}
