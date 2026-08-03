# S3：循环越界

## 原理描述

在循环语句中拷贝数据，循环次数被循环体改变，或者被循环体调用的函数改变，导致读写内存溢出。

## 漏洞特征

在循环迭代中涉及对缓冲区的读写内存操作；循环迭代的次数不固定，也不取决于目的缓冲区；目的缓冲区和源缓冲区长度不可控制，甚至可能是用户输入的一些数据。

### 循环次数递增导致溢出

问题代码示例如下：len受攻击者控制。


```c
for(int i = 0; i < len; i++)
{
     target[i]=source[i]
}
```



### 循环次数被循环体改变导致溢出

在循环里拷贝数据，循环次数被循环体改变，或者被循环体调用的函数改变，导致溢出, 如下代码所示：


```c
while(ulLength > 0 )
{
        ……………………….
        ulCopyLength=GetAvpLen(pMsg);
		ulCopyLength=( ulCopyLength, MAX_LEN);
        VOS_MemCpy_Safe(pucBuffer,MAX_LEN,pMsg->pucData+ ulOffset, ulCopyLength);
        ulLength -= ulCopyLength;
        pucBuffer += ulCopyLength;
        ……………………….
}
```



### 从报文里取出循环次数，未判断就使用

循环次数直接从消息中获取，未做校验，导致循环体内的拷贝函数越界，如下代码所示：


```c
VOS_VOID XXXMsgProc(MSG_XXX_STRU* msg)
{
	VOS_UCHAR aucTmpBuf[MAX _BUF_LEN + 1]    = {0};
………………………
    for (ulLoop = 0; ulLoop < msg ->usNum; ulLoop++)
    {
………………………
      memcpy_sp(aucTmpBuf + pos, tid_len, tid, tid_len);
      pos += tid_len
………………………
     }
}
```



## 潜在风险

缓冲区溢出最危险的是堆栈内存溢出，攻击者利用堆栈溢出，改写保留在堆栈中的函数地址，达到控制程序执行。带来的危害一种是程序崩溃导致拒绝服务， 另外一种就是执行一段恶意代码， 获得系统的最高权限。

## 相关案例

### 案例一


```c
int Frame_DealBufIniToHash(void *pBuf)
{
	char acBuffer[INI_LINE_LEN] = {0};
	int iRet = 0;
	int inum = 0;
	int ilen = 0;
	char *pcTmp = NULL;
	    …
	    pcTmp = (char *)pBuf;
	    …
	while ( ( ilen > 0 ) && pcTmp && !CHAR_IS_SPACE(*pcTmp) )
	{
	   acBuffer[inum++] = *pcTmp;
	   pcTmp++;
	   ilen--;
	 }
	    ….
}
```


对于外部输入pcTmp长度缺少校验，直接拷贝，导致缓冲区写溢出。
