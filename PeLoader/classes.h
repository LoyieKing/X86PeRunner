/* 
 * Yet Another Code Translator (c) mamaich, 2011
 *
 * Support classes (containters, locks, etc)
 *
 *
 */

#ifndef __CLASSES_H
#define __CLASSES_H

#include <windows.h>
#include <malloc.h>

#ifdef __cplusplus

// Critical section class. Unlocks automatically when destructor called. 
// Call FreeCS() to release memory allocated by crit section when it is no longer needed.
// Do not delete CS in destructor, as it may be allocated by caller.
class CLock
{
private:
	bool OwnCS;
	LPCRITICAL_SECTION *CS;
    int Count;
	void FreeCS()
	{
#ifdef _DEBUG
		if(Count>0)
			__debugbreak();
#endif
		if(OwnCS)
		{
			DeleteCriticalSection(*CS);
			delete *CS;
			*CS=0;
		}
	}
public:
    CLock(LPCRITICAL_SECTION *Cs)
    {
    	if(*Cs==0)
    	{
    	    *Cs=new CRITICAL_SECTION;
            InitializeCriticalSection(*Cs); 
			OwnCS=true;
    	} else
			OwnCS=false;
    	CS=Cs;
    	Count=0;
    }
    void Lock()
    {
    	EnterCriticalSection(*CS);
    	Count++;
    }
    void Unlock()
    {
        if(Count>0)
        {
    	    Count--;
    	    LeaveCriticalSection(*CS);
    	} else
			__debugbreak();
    }
    ~CLock()
    {
		if(Count>0)
			Unlock();	// allow L.Unlock() then delete L, and delete L without Unlock (prefered);
        FreeCS();
    }
};

// Set. Associates void* pointer with int index.
class CSet
{
	LPCRITICAL_SECTION Cs;
	CLock L;
	void ****Ptrs[256];
public:
	CSet() : Cs(0), L(&Cs)
	{
		memset(Ptrs,0,sizeof(Ptrs));
	}

	bool Set(unsigned int Idx, void* Data)
	{
		int i=(Idx>>24)&255;
		int j=(Idx>>16)&255;
		int k=(Idx>>8)&255;
		int l=Idx&255;
		L.Lock();
		if(Ptrs[i]==0)
		{
			Ptrs[i]=(void****)malloc(256*sizeof(void****));
			if(Ptrs[i]==0)
				return false;
			memset(Ptrs[i],0,256*sizeof(void****));
		}
		if(Ptrs[i][j]==0)
		{
			Ptrs[i][j]=(void***)malloc(256*sizeof(void***));
			if(Ptrs[i][j]==0)
				return false;
			memset(Ptrs[i][j],0,256*sizeof(void***));
		}
		if(Ptrs[i][j][k]==0)
		{
			Ptrs[i][j][k]=(void**)malloc(256*sizeof(void**));
			if(Ptrs[i][j][k]==0)
				return false;
			memset(Ptrs[i][j][k],0,256*sizeof(void**));
		}
		Ptrs[i][j][k][l]=Data;
		L.Unlock();
		return true;
	}

	void *Get(unsigned int Idx)
	{
		int i=(Idx>>24)&255;
		int j=(Idx>>16)&255;
		int k=(Idx>>8)&255;
		int l=Idx&255;
		void* Ret=NULL;
		L.Lock();
		if(Ptrs[i]==0)
			goto Done;
		if(Ptrs[i][j]==0)
			goto Done;
		if(Ptrs[i][j][k]==0)
			goto Done;
		Ret=Ptrs[i][j][k][l];
Done:
		L.Unlock();
		return Ret;
	}

	~CSet()
	{
		L.Lock();
		for(int i=0; i<256; i++)
		{
			if(Ptrs[i])
			{
				for(int j=0; j<256; j++)
				{
					if(Ptrs[i][j])
					{
						for(int k=0; k<256; k++)
							if(Ptrs[i][j][k])
								free(Ptrs[i][j][k]);
						free(Ptrs[i][j]);
					}
				}
				free(Ptrs[i]);
			}
		}
		L.Unlock();
	}

typedef bool t_Func(unsigned int Idx, void *Data, void *Param);	// return true to continue, false to break enum
	void ForEach(t_Func *CB, void *Param)
	{
		L.Lock();
		for(int i=0; i<256; i++)
		{
			if(Ptrs[i])
			{
				for(int j=0; j<256; j++)
				{
					if(Ptrs[i][j])
					{
						for(int k=0; k<256; k++)
							if(Ptrs[i][j][k])
							{
								for(int l=0; l<256; l++)
									if(!CB(l+(k<<8)+(j<<16)+(i<<24),Ptrs[i][j][k][l],Param))
										goto Done;
							}
					}
				}
			}
		}
Done:
		L.Unlock();
	}
};

// Linked List of void* pointers
class CList
{
	LPCRITICAL_SECTION Cs;
	CLock L;
	struct ListItem
	{
		ListItem *Next;
		void *Data;
	};

	ListItem *Head;
	ListItem *Tail;
public:
	CList() : Cs(0), L(&Cs)
	{
		Head=Tail=0;
	}

	bool AddHead(void *Data)
	{
		L.Lock();
		ListItem *Tmp=(ListItem*)malloc(sizeof(ListItem));
		if(Tmp==0)
		{
			L.Unlock();
			return false;
		}
		Tmp->Next=Head;
		Tmp->Data=Data;
		if(Head==0)
			Tail=Tmp;
		Head=Tmp;
		L.Unlock();
		return true;
	}

	bool AddTail(void *Data)
	{
		L.Lock();
		ListItem *Tmp=(ListItem*)malloc(sizeof(ListItem));
		if(Tmp==0)
		{
			L.Unlock();
			return false;
		}
		Tmp->Next=0;
		Tmp->Data=Data;
		if(Tail)
			Tail->Next=Tmp;
		else
			Head=Tmp;
		Tail=Tmp;
		L.Unlock();
		return true;
	}

	void *GetHead(void)
	{
		L.Lock();
		void *TmpD=0;
		if(Head!=0)
		{
			ListItem *Tmp=Head;
			TmpD=Head->Data;
			Head=Head->Next;
			free(Tmp);
			if(Head==0)
				Tail=0;
		}
		L.Unlock();
		return TmpD;
	}

	~CList()
	{
		L.Lock();
		while(Head)
		{
			ListItem *Tmp=Head;
			Head=Tmp->Next;
			free(Tmp);
		}
		L.Unlock();
	}

typedef bool t_Func(void *Data, void *Param);	// return true to continue, false to break enum
	void ForEach(t_Func *CB, void *Param)
	{
		L.Lock();
		ListItem *Tmp=Head;
		while(Tmp)
		{
			if(!CB(Tmp->Data,Param))
				break;
			Tmp=Tmp->Next;
		}
		L.Unlock();
	}
};

#endif // __cplusplus

#endif // __CLASSES_H
