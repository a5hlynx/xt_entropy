/*
	Shannon Entropy X-Tension
	Copyright (C) 2020 Yuya Hashimoto

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published
	by the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.

	XT_ functions starting in this program were implemented referring to
	the X-Tension below.
	- Griffeye XML export X-Tension for X-Ways Forensics
	- Copyright (C) 2019 R. Yushaev
	- https://github.com/Naufragous/xt-gexpo/
*/

#include "X-tension.h"
#include <math.h>
#include <windows.h>
#include <stdio.h>
#include <direct.h>
#include <strsafe.h>
#include <cmath>

#define MIN_VER	1990
#define NAME_BUF_LEN 256
#define MSG_BUF_LEN 1024
#define VER_BUF_LEN 10

int xwf_version = 0;
const wchar_t* XT_VER = L"XT_ENTROPY - v1.0.0";

WCHAR case_name[NAME_BUF_LEN] = { 0 };
wchar_t msg[MSG_BUF_LEN];
wchar_t VER[VER_BUF_LEN];

BOOLEAN EXIT = FALSE;

struct XtFileId {
	LONG xwf_id;
};

struct XtVolume {
	struct XtVolume* next;
	struct XtFileId* file_ids;
	INT64 file_count;
	WCHAR name[NAME_BUF_LEN];
};

struct XtVolume* first_volume = NULL;
struct XtVolume* current_volume = NULL;

double CalcEntropyInByte(BYTE* filebuf, DWORD fsize){

	double entropy = 0.0, freq = 0.0;
	unsigned long int freqList[256] = { 0 };
	for (DWORD i = 0; i < fsize; i++){
		freqList[filebuf[i]] += 1;
	}
	DWORD fileSize = fsize;
	for (int i = 0; i < 256; i++){
		if (freqList[i] > 0){
			freq = double(freqList[i]) / fileSize;
			entropy = entropy + freq * std::log2(freq);
		}
	}
	if (entropy < 0){
		entropy = -1 * entropy;
	}
	return entropy;
}

BOOL SetCurrentVolume(LPWSTR name){

	struct XtVolume* previous = first_volume;
	struct XtVolume* current = previous;

	while (current){
		if (wcscmp(name, current->name) == 0){
			current_volume = current;
			return TRUE;
		}
		previous = current;
		current = current->next;
	}
	current_volume = (XtVolume*)calloc(1, sizeof(struct XtVolume));
	if (previous){
		previous->next = current_volume;
	} else {
		first_volume = current_volume;
	}
	return FALSE;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Init
LONG __stdcall XT_Init(CallerInfo info, DWORD nFlags, HANDLE hMainWnd, void* lpReserved){

	if ( (XT_INIT_XWF & nFlags) == 0 ||
		  XT_INIT_WHX & nFlags ||
		  XT_INIT_XWI & nFlags ||
		  XT_INIT_BETA & nFlags
	){
		return -1;
	}

	if ( XT_INIT_ABOUTONLY & nFlags ||
		 XT_INIT_QUICKCHECK & nFlags
	){
		return 1;
	}

	XT_RetrieveFunctionPointers();

	if (info.version < MIN_VER){
		wcscpy_s(msg, L"XT_ENTROPY: The Version of X-Ways Forensics must be v.");
		swprintf_s(VER, L"%d", MIN_VER);
		wcscat_s(msg, VER);
		wcscat_s(msg, L" or Later. Exiting...");
		XWF_OutputMessage(msg, 0);
		EXIT = TRUE;
		return 1;
	}

	if (XWF_GetCaseProp(NULL, XWF_CASEPROP_TITLE, case_name, NAME_BUF_LEN) == -1){
		XWF_OutputMessage(L"XT_ENTROPY: Active Case is Required. Exiting...", 0);
		EXIT = TRUE;
		return 1;
	}

	if (!XWF_GetFirstEvObj(NULL)){
		XWF_OutputMessage(L"XT_ENTROPY: No Evidence is Found. Exiting...", 0);
		EXIT = TRUE;
		return 1;
	}

	current_volume = (XtVolume*)calloc(1, sizeof(struct XtVolume));
	first_volume = current_volume;
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done
LONG __stdcall XT_Done(void* lpReserved){

	if (EXIT) {
		return 0;
	}
	struct XtVolume* tmp = NULL;
	struct XtVolume* vol = first_volume;
	while (vol){
		free(vol->file_ids);
		vol->file_ids = NULL;
		tmp = vol;
		vol = vol->next;
		free(tmp);
		tmp = NULL;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About
LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved){

	MessageBox(NULL, (wchar_t*)XT_VER, TEXT("about"), MB_OK);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare
LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved){

	if (EXIT) {
		return -1;
	}
	LONG return_value = 0;
	switch (nOpType){
		case XT_ACTION_RUN:
			XWF_OutputMessage(L"XT_ENTROPY: Not Supposed to be Executed from the Tools Menu. Exiting...",0);
			return -1;
		case XT_ACTION_LSS:
		case XT_ACTION_PSS:
		case XT_ACTION_SHC:
			XWF_OutputMessage(L"XT_ENTROPY: Not Supposed to be Executed during Searches. Exiting...", 0);
			return -3;
		case XT_ACTION_RVS:
			return_value = XT_PREPARE_CALLPI | XT_PREPARE_CALLPILATE;
			break;
		case XT_ACTION_DBC:
			return_value = 0;
			break;
		default:
			XWF_OutputMessage(L"XT_ENTROPY: Does Not Support this Mode of Operation. Exiting...", 0);
			return -1;
	}
	WCHAR longname[NAME_BUF_LEN];
	WCHAR shortname[NAME_BUF_LEN];
	XWF_GetVolumeName(hVolume, longname, 1);
	XWF_GetVolumeName(hVolume, shortname, 0);

	if (wcsstr(longname, shortname) == NULL){
		size_t pos = wcslen(shortname);
		while (pos > 1){
			if (shortname[pos--] == L' ' && shortname[pos] == L','){
				shortname[pos] = L'\0';
				break;
			}
		}
	}
	for (int i = 0; i < wcslen(shortname); i++){
		switch (shortname[i]){
			case L'\\':
			case L'/':
			case L':':
			case L'*':
			case L'?':
			case L'\"':
			case L'<':
			case L'>':
			case L'|':
				shortname[i] = L'_';
		}
	}
	BOOL volume_exists = SetCurrentVolume(shortname);
	DWORD item_count = XWF_GetItemCount(NULL);
	if (current_volume->file_ids){
		free(current_volume->file_ids);
	}
	current_volume->file_ids = (XtFileId*)malloc(sizeof(struct XtFileId) * item_count);
	current_volume->file_count = 0;
	if (volume_exists){
		return return_value;
	}
	return XT_PREPARE_CALLPI;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize
LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved){

	if (EXIT){
		return 0;
	}
	const INT64 fc = current_volume->file_count;
	if (fc == 0 || current_volume->file_ids == NULL){
		return 0;
	}
	struct XtFileId* file_ids = current_volume->file_ids;

	XWF_ShowProgress((wchar_t*)TEXT("Calculating Shannon Entropy..."), 4);
	XWF_SetProgressPercentage(0);

	for (INT64 i = 0; i < fc; i++){
		if (XWF_ShouldStop()){
			return 1;
		}
		HANDLE hItem = XWF_OpenItem(hVolume, file_ids[i].xwf_id, 1);
		if (hItem != 0) {
			INT64 expected_size = XWF_GetSize(hItem, (LPVOID)1);
			LPVOID filebuf = malloc(expected_size);
			WCHAR item[NAME_BUF_LEN];
			wcscpy_s(item, XWF_GetItemName(file_ids[i].xwf_id));
			item[wcslen(item)] = L'\0';
			XWF_SetProgressDescription(item);
			if (filebuf == NULL){
				XWF_Close(hItem);
				wcscpy_s(msg, L"XT_ENTROPY: Unable to Allocate Memory for \"");
				wcscat_s(msg, item);
				wcscat_s(msg, L"\". Skipping...");
				XWF_OutputMessage(msg, 0);
				continue;
			}
			DWORD actual_size = XWF_Read(hItem, 0, (BYTE*)filebuf, (DWORD)expected_size);
			XWF_Close(hItem);
			if (actual_size != 0){
				double entropy = CalcEntropyInByte((BYTE*)filebuf, actual_size);
				TCHAR ent[64];
				swprintf_s(ent, TEXT("%1.16lf"), entropy);
				XWF_AddComment(file_ids[i].xwf_id, ent, 0x00);
			} else {
				wcscpy_s(msg, L"XT_ENTROPY: Unable to Calculate Entropy for 0-Byte File \"");
				wcscat_s(msg, item);
				wcscat_s(msg, L"\". Skipping...");
				XWF_OutputMessage(msg, 0);
			}
			free(filebuf);
		}
		XWF_SetProgressPercentage((DWORD)(i * 100 / fc));
	}
	XWF_HideProgress();
	free(current_volume->file_ids);
	current_volume->file_ids = NULL;
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItem
LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved){

	if (EXIT) {
		return -1;
	}
	if (current_volume == NULL) {
		XWF_OutputMessage(L"XT_ENTROPY: Unable to Associate the File with a Volume. Exiting...", 0);
		return -1;
	}
	INT64 fc = current_volume->file_count++;
	current_volume->file_ids[fc].xwf_id = nItemID;
	return 0;
}