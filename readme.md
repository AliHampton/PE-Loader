# PE Loader

Manually loads a executable file from disk; Maps a physical file to virtual memory and calls the entry point.
In simple terms this project runs an executable without using the windows API to start the program as it manually loads it from disk. It will handle all virtual address translation and importation of dependencies. 
