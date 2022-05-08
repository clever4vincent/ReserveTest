// TTDLL.h: interface for the TTDLL class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TTDLL_H__12BDA600_3C58_4DB7_8882_79C2AEACD722__INCLUDED_)
#define AFX_TTDLL_H__12BDA600_3C58_4DB7_8882_79C2AEACD722__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

extern "C" _declspec(dllexport) int __stdcall  Plus (int x,int y);
extern "C" _declspec(dllexport) int __stdcall  Sub (int x,int y);
extern "C" _declspec(dllexport) int __stdcall  Mul (int x,int y);
extern "C" _declspec(dllexport) int __stdcall  Div (int x,int y);

#endif // !defined(AFX_TTDLL_H__12BDA600_3C58_4DB7_8882_79C2AEACD722__INCLUDED_)
