void memoryobfuscation(){
  FILE* f = fopen('C:\\something.txt', 'wb');
  fwrite(&{{PROCESS_SPAWN}}, 1, f);
  fclose(f);
}
