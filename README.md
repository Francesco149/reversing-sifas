this is a collection of info about love live all stars' internals that I
collect and add as I reverse engineer it

this information is public domain. feel free to use it and republish it
however you please

I installed the game on android x86 on a PC (had to unroot android to make
it run) and fully updated it.

then i hooked up the android ssd to my linux machine, mounted it and
searched for any file that contained lovelive in the path and copied
everything

`split_config.armeabi_v7a.apk` contains the native binaries (lib folder)

`base.apk` contains assets and the java glue for unity

i used apktool 2.4.0 to extract the apk's

game uses unity. as of 2019-10-04, the version is 2018.4.2f1
(found in `base.apk/smali/com/unity3d/player/m.smali`)

```smali
    const-string v2, "Unity version     : %s\n"

    new-array v4, v3, [Ljava/lang/Object;

    const-string v5, "2018.4.2f1"
```

unity uses il2cpp to transpile C# assembly to C++ and compile it to a
native android shared library named il2cpp.so located in
`split_config.armeabi_v7a.apk/lib/arm`

interestingly, all stars only ships with arm binaries while the japanese
version of the old sif game had x86 binaries as well

using Il2CppDumper v4.6.0 it's possible to recover the method names and
strings by giving it the il2cpp.so first and then the global-metadata.dat
located in `base.apk/assets/bin/Data/Managed/Metadata` . it should do it
automatically, remember to specify 2018.4 as the unity version.

Il2CppDumper generates a script.py for IDA. but since i use ghidra instead
of IDA's proprietary garbage, I used this script by worawit:
https://gist.github.com/Francesco149/289a24d2f17ba60f820f801b8bd6754a
for ghidra which takes the IDA script as input and renames everything

I now have a mostly named disassembly and we have also recovered all the
string constants so reversing stuff should be much easier this way

after skimming through the strings (they all have the `StringLiteral_`
prefix), i found three interesting strings referenced by
`ServerConfig$$.cctor`

```
https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1002
i0qzc6XbhFfAxjN2
x\'B73DA9C0EE7116836995B5ACED4AA33B095ECAF77B33605833FD759E6E743F1D\'
```

which I speculatively named ServerHost, ServerPassword and ServerKey

the disassembly of that ServerConfig ctor reveals that they're using a
library named DotUnder

```c
void ServerConfig$$.cctor(void)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;

  if (DAT_037021b1 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x8c63);
  }
  **(undefined4 **)(Class$DotUnder.ServerConfig + 0x5c) = ServerHost;
  piVar2 = (int *)Encoding$$get_UTF8(0);
  if (piVar2 == (int *)0x0) {
    FUN_0089db60(0);
  }
  uVar3 = (**(code **)(*piVar2 + 0x148))(piVar2,ServerPassword,*(undefined4 *)(*piVar2 + 0x14c));
  iVar1 = Class$DotUnder.ServerConfig;
  *(undefined4 *)(*(int *)(Class$DotUnder.ServerConfig + 0x5c) + 4) = uVar3;
  *(undefined4 *)(*(int *)(iVar1 + 0x5c) + 8) = ServerKey;
  *(undefined4 *)(*(int *)(iVar1 + 0x5c) + 0xc) = StringLiteral_7288;
  *(undefined *)(*(int *)(iVar1 + 0x5c) + 0x10) = 0;
  return;
}
```

however, googling DotUnder doesn't seem to yield any results so it's
probably an internal library

we can use getter names to figure out what the fields of the ServerConfig
struct are though, for example:

```c
undefined4 Config$$get_StartupKey(void)

{
  if (DAT_03704350 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x26ce);
  }
  if (((*(byte *)(Class$DotUnder.ServerConfig + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.ServerConfig + 0x70) == 0)) {
    FUN_0087fd40();
  }
  return *(undefined4 *)(*(int *)(Class$DotUnder.ServerConfig + 0x5c) + 4);
}
```

this tells us that what we named ServerPassword is originally named
StartupKey. why? because it's returning offset 4 of ServerConfig + 0x5c,
which is the same that is assigned in the ctor

```c
  uVar3 = (**(code **)(*piVar2 + 0x148))(piVar2,ServerPassword,*(undefined4 *)(*piVar2 + 0x14c));
  iVar1 = Class$DotUnder.ServerConfig;
  *(undefined4 *)(*(int *)(Class$DotUnder.ServerConfig + 0x5c) + 4) = uVar3;
```

by browsing all references to ServerConfig I renamed ServerHost to
ServerEndpoint and ServerPassword to StartupKey.

I couldn't find any reference to the ServerKey offset, so for now I'm
leaving it.

using ghidra's data type manager and checking all the getter names as
before I map out the ServerConfig struct. this makes the decompile output
a whole lot more readable.

I also figured out that each object has the same wrapper struct where you
have a pointer to the actual data at 0x5c. I saw other object being checked
at the same offsets

```c
void ServerConfig$$.cctor(void)

{
  Object *config;
  int *utf8;
  char *utf8StartupKey;

  if (DAT_037021b1 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x8c63);
  }
  Class$DotUnder.ServerConfig->Instance->ServerEndpoint = ServerEndpoint;
  utf8 = (int *)Encoding$$get_UTF8(0);
  if (utf8 == (int *)0x0) {
    FUN_0089db60(0);
  }
  utf8StartupKey =
       (char *)(**(code **)(*utf8 + 0x148))(utf8,StartupKey,*(undefined4 *)(*utf8 + 0x14c));
  config = Class$DotUnder.ServerConfig;
  Class$DotUnder.ServerConfig->Instance->StartupKey = utf8StartupKey;
  config->Instance->ServerKey = ServerKey;
  config->Instance->BuildId = BuildId;
  config->Instance->Unk1 = false;
  return;
}
```

after digging around some more I found this class named DMHttpApi which has
a method named CalcDigest called in MakeRequestData which does a
hmac sha-1 hash with the given params. so far it all seems very similar to
how the original sif request signing worked

upon further inspection, MakeRequestData takes 2 strings and concatenates
them with a space in between, then does a hmac-sha1 using some key stored
in DMHttpApi

```c
Array * DMHttpApi$$CalcDigest(Array *param_1,Array *param_2,int param_2_index,int param_2_len)

{
  System.Text.Encoding *enc;
  Array *param_1_bytes;
  Array *param_4_1;
  undefined4 uVar1;
  Array *key;
  uint param_1_len;
  
  if (DAT_037033d9 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x2bcc);
  }
  enc = Encoding$$get_UTF8((System.Text.Encoding *)0x0);
  if (enc == (System.Text.Encoding *)0x0) {
    ThrowException(0);
  }
  param_1_bytes = (Array *)(*enc->vtable->DoSomething)(enc,param_1,enc->vtable->SomePredicateFunc);
  if (param_1_bytes == (Array *)0x0) {
    ThrowException(0);
  }
  param_4_1 = (Array *)Instantiate(Class$byte[],param_2_len + param_1_bytes->Length + 1);
  if (param_1_bytes == (Array *)0x0) {
    ThrowException(0);
    Array$$Copy(0,0,param_4_1,0,_DAT_0000000c);
    ThrowException(0);
  }
  else {
                    /* param_4_1 = param_1_bytes
                       
                       Array.Copy(src, srcIndex, dst, dstIndex, len) */
    Array$$Copy(param_1_bytes,0,param_4_1,0,param_1_bytes->Length);
  }
  if (param_4_1 == (Array *)0x0) {
    ThrowException(0);
  }
  param_1_len = param_1_bytes->Length;
  if ((uint)param_4_1->Length <= param_1_len) {
    uVar1 = FUN_0089ec04();
    ThrowSomeOtherException(uVar1,0,0);
  }
                    /* append a space to param_4_1 */
  (&param_4_1->Data)[param_1_len] = ' ';
                    /* append param_2[param_2_index,param_2_len] to param_4_1 */
  Array$$Copy(param_2,param_2_index,param_4_1,param_1_bytes->Length + 1,param_2_len);
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  key = Class$DotUnder.DMHttpApi->Instance->HmacSha1Key;
  if (((Class$DotUnder.DMCryptography->BitField1 & 2) != 0) &&
     (Class$DotUnder.DMCryptography->Unk1 == 0)) {
    FUN_0087fd40();
  }
  DMCryptography$$HmacSha1(param_4_1,key);
  param_4_1 = (Array *)Lib$$Hexlify();
  return param_4_1;
}
```

a quick search for references to HmacSha1Key in DMHttpApi tells us that
it's internally called SessionKey

```c
undefined4 DMHttpApi$$CopySessionKey(undefined4 param_1)

{
  undefined4 uVar1;
  
  if (DAT_037033d8 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x2bcf);
  }
  uVar1 = Instantiate(Class$byte[],param_1);
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  Array$$Copy(Class$DotUnder.DMHttpApi->Instance->HmacSha1Key,uVar1,param_1,0);
  return uVar1;
}
```

looking for references to the SessionKey field I found this, which looks
very similar to the old SIF request signing

```c
void DMHttpApi.__c__DisplayClass14_1$$_Login_b__1(int param_1,int param_2)

{
  undefined4 uVar1;
  Array *pAVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  
  if (DAT_037033e2 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0xb482);
  }
  uVar4 = *(undefined4 *)(param_1 + 8);
  if (param_2 == 0) {
    ThrowException(0);
  }
  uVar1 = LoginResponse$$get_SessionKey(param_2,0);
  if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
     (*(int *)(Class$System.Convert + 0x70) == 0)) {
    FUN_0087fd40();
  }
  uVar1 = Convert$$FromBase64String(uVar1,0);
  pAVar2 = (Array *)Lib$$XorBytes(uVar4,uVar1);
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  Class$DotUnder.DMHttpApi->Instance->SessionKey = pAVar2;
  if (param_2 == 0) {
    ThrowException(0);
  }
  uVar5 = LoginResponse$$get_LastTimestamp(param_2,0);
  Clock$$SetLastTimestamp((int)((ulonglong)uVar5 >> 0x20),(int)uVar5,0);
  iVar3 = *(int *)(param_1 + 0x14);
  if (iVar3 == 0) {
    ThrowException(0);
  }
  iVar3 = *(int *)(iVar3 + 8);
  if (iVar3 == 0) {
    ThrowException(0);
  }
  FUN_023a2ee8(iVar3,param_2,Method$Action_LoginResponse_.Invoke());
  return;
}
```

so essentially what's happening is some http request response contains a
base64 key which is then decoded and xored with a xor key string. the
result is used as the session key

this appears to be the xor key:

```c
  uVar4 = *(undefined4 *)(param_1 + 8);

  ...

  pAVar2 = (Array *)Lib$$XorBytes(uVar4,uVar1);
```

param_1 appears to be some class instance, let's map the struct with just
the xor key field for now

as for param_2, we can deduce that it's a LoginResponse instance since it's
passed as the this pointer for `LoginResponse$$get_SessionKey`

let's map some of LoginResponse's field by looking at its getters

```c
undefined4 LoginResponse$$get_UserModel(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}

undefined4 LoginResponse$$get_SessionKey(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}

uint LoginResponse$$get_IsPlatformServiceLinked(int param_1)

{
  return (uint)*(byte *)(param_1 + 0x10);
}

undefined8 LoginResponse$$get_LastTimestamp(int param_1)

{
  return CONCAT44(*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x1c));
}

undefined4 LoginResponse$$get_Cautions(int param_1)

{
  return *(undefined4 *)(param_1 + 0x20);
}

uint LoginResponse$$get_ShowHomeCaution(int param_1)

{
  return (uint)*(byte *)(param_1 + 0x24);
}

undefined4 LoginResponse$$get_LiveResume(int param_1)

{
  return *(undefined4 *)(param_1 + 0x28);
}
```

by looking at `DMHttpApi$$Logout` we can map a few unknown fields for
DMHttpApi as well as the connection field

```c
void DMHttpApi$$Logout(void)

{
  DMHttpApiObject *pDVar1;
  DMHttpApi *pDVar2;
  int iVar3;

  if (DAT_037033d6 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x2bd3);
  }
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  iVar3 = *(int *)&Class$DotUnder.DMHttpApi->Instance->field_0xc;
  if (iVar3 != 0) {
    if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
      FUN_0087fd40();
      iVar3 = *(int *)&Class$DotUnder.DMHttpApi->Instance->field_0xc;
      if (iVar3 == 0) {
        iVar3 = 0;
        ThrowException(0);
      }
    }
    Network.Connection$$Cancel(iVar3,0);
    if (((*(byte *)(_Class$DotUnder.HttpSubject + 0xbf) & 2) != 0) &&
       (*(int *)(_Class$DotUnder.HttpSubject + 0x70) == 0)) {
      FUN_0087fd40();
    }
    HttpSubject$$OnCancel();
  }
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  pDVar2 = Class$DotUnder.DMHttpApi->Instance;
  *(undefined4 *)&pDVar2->field_0x4 = 0;
  *(undefined4 *)pDVar2 = 0;
  pDVar1 = Class$DotUnder.DMHttpApi;
  Class$DotUnder.DMHttpApi->Instance->SessionKey = (Array *)0x0;
  *(undefined4 *)&pDVar1->Instance->field_0xc = 0;
  *(undefined4 *)&pDVar1->Instance[1].field_0x1 = 0;
  *(undefined4 *)&pDVar1->Instance[1].field_0x5 = 0;
  return;
}
```

by looking at DmHttpApi's getters i was able to name the field IsGuarded

at this point i just start looking at every DmHttpApi method, this seems
to be a simple counter, and tells me that that Unk3 field is the request id

```c
void DMHttpApi$$CreateRequestId(void)

{
  DMHttpApiObject *pDVar1;
  
  if (DAT_037033da == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x2bd0);
  }
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  pDVar1 = Class$DotUnder.DMHttpApi;
  Class$DotUnder.DMHttpApi->Instance->Unk3 = Class$DotUnder.DMHttpApi->Instance->Unk3 + 1;
  FUN_01746d54(&pDVar1->Instance->Unk3,0);
  return;
}
```

that function call at the end appears to stringify it, so I assume this
returns a string

in `DMHttpApi.__c__DisplayClass14_1$$_Login_b__2` i found a reference to
some UserKey class, we'll take a look at that later

more familiar base64 xoring in this login step, also it references
StartupResponse which I should probably start mapping

```c

void DMHttpApi.__c__DisplayClass14_2$$_Login_b__4(int param_1,int param_2)

{
  undefined4 uVar1;
  Array *string;
  int iVar2;
  Array *pAVar3;

  if (DAT_037033e5 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0xb486);
  }
  if (param_2 == 0) {
    ThrowException(0);
    uVar1 = StartupResponse$$get_UserId(0,0);
    pAVar3 = *(Array **)(param_1 + 8);
    ThrowException(0);
  }
  else {
    uVar1 = StartupResponse$$get_UserId(param_2,0);
    pAVar3 = *(Array **)(param_1 + 8);
  }
  string = (Array *)StartupResponse$$get_AuthorizationKey(param_2,0);
  if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
     (*(int *)(Class$System.Convert + 0x70) == 0)) {
    FUN_0087fd40();
  }
  string = Convert$$FromBase64String(string);
  pAVar3 = Lib$$XorBytes(pAVar3,string);
  UserKey$$SetIDPW(uVar1,pAVar3,0);
  iVar2 = *(int *)(param_1 + 0xc);
  if (iVar2 == 0) {
    ThrowException(0);
  }
  iVar2 = *(int *)(iVar2 + 0x10);
  if (iVar2 == 0) {
    ThrowException(0);
  }
  FUN_023b38fc(iVar2,uVar1,pAVar3,Method$Action_int_-byte[]_.Invoke());
  return;
}
```

I mapped Connection and StartupResponse fields based on the getters as
usual. probably unnecessary

at this point I start looking through strings again and I find strings that
are most likely api endpoints, most of them referenced by various methods

```
/login/startup
/live/surrender
/navi/tapLovePoint
/terms/agreement
/tutorial/phaseEnd
```

and so on

let's take a look at what references `/login/startup`

```c
undefined4 Startup$$get_Path(void)

{
  if (DAT_036ffcc5 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x92cd);
  }
  return login_startup;
}
```

while looking through the Startup methods I notice that ghidra is actually
failing to disassemble a lot of the code because it thinks some functions
aren't returning. I should've disabled non-returning function discovery on
the analysis settings. I'm going to re-run the analysis. this kind of thing
should also be fixable by doing `func.setNoReturn(False)`

re-analyzing didn't fix, had to manually right click the flow override
comments and set flow to default

finally `StartupRequestBuilder$$Create` disassembles properly as well as
many other similar functions that used to only be a Instantiate1 call

```c
void StartupRequestBuilder$$Create(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  if (DAT_037021c9 == '\0') {
                    /* WARNING: Subroutine does not return */
    FUN_008722e4(0x92cb);
  }
  uVar1 = Clock$$get_TimeDifference(0);
  uVar2 = Instantiate1(Class$DotUnder.Structure.StartupRequest);
  StartupRequest$$.ctor(uVar2,param_1,StringLiteral_73,uVar1,0);
  if (param_2 == 0) {
    ThrowException(0);
  }
  FUN_023a2ee8(param_2,uVar2,Method$Action_StartupRequest_.Invoke());
  return;
}
```

I'm not sure how to automatically fixup this thing globally so for now I'm
manually fixing the flow where needed

this also fixed the disassembly for the Serialization functions which
now tell us exactly what fields the request should have

```c
int Serialization$$SerializeStartupRequest(int *param_1)

{
  /* ... */

  iVar3 = StartupRequest$$get_Mask(param_1,0);
  if (iVar3 != 0) {
    if (bVar1) {
      ThrowException(0);
    }
    uVar4 = StartupRequest$$get_Mask(param_1,0);
    if (iVar2 == 0) {
      ThrowException(0);
    }
    FUN_023742d0(iVar2,mask,uVar4,Method$Dictionary_string_-object_.set_Item());
  }
  if (bVar1) {
    ThrowException(0);
  }
  iVar3 = StartupRequest$$get_ResemaraDetectionIdentifier(param_1,0);
  if (iVar3 != 0) {
    if (bVar1) {
      ThrowException(0);
    }
    uVar4 = StartupRequest$$get_ResemaraDetectionIdentifier(param_1,0);
    if (iVar2 == 0) {
      ThrowException(0);
    }
    FUN_023742d0(iVar2,resemara_detection_identifier,uVar4,
                 Method$Dictionary_string_-object_.set_Item());
  }
  if (bVar1) {
    ThrowException(0);
  }
  uStack32 = StartupRequest$$get_TimeDifference(param_1,0);
  uVar4 = FUN_008ae744(Class$int,&uStack32);
  if (iVar2 == 0) {
    ThrowException(0);
  }
  FUN_023742d0(iVar2,time_difference,uVar4,Method$Dictionary_string_-object_.set_Item());
  return iVar2;
}
```

the `FUN_023742d0` calls set request fields and the second argument is the
field name

this "resemara detection" is intriguing. after searching for resemara
in the symbols table i found `AndroidPlatform$$LoadResemaraDetectionIdentifier`

halfway into this function it passes the string "getResemaraDetectionId"
to a function:

```c
  uVar5 = FUN_0149a010(piVar1,getResemaraDetectionId,piVar3,
                       Method$AndroidJavaObject.CallStatic()_AndroidJavaObject_);
```

this is very familiar, it's calling into java code, and I imagine piVar1
is a java context object of some sort.

time to decompile the java side

for some reason dragging ```base.apk``` into my current ghidra project
wasn't working (it wouldn't show classes.dex to decompile) so I created a
new project and imported ```base.apk``` which correctly decompiled

you will notice that there's strings defined with a scrambled version of
each function name. this was also present in old SIF, I think it's just
something that java does:

```
                             **************************************************************
                             * 4ebf                                                       *
                             *                                                            *
                             * createResemaraDetectionId                                  *
                             **************************************************************
                             strings::createResemaraDetectionId              XREF[1]:     00013b6c(*)  
        003a3fa2 19 63 72        string_d
                 65 61 74 
                 65 52 65 
           003a3fa2 19              db[1]                             utf16_size                        XREF[1]:     00013b6c(*)  
              003a3fa2 [0]            19h
           003a3fa3 63 72 65 61 74  utf8      u8"cetRsmrDtcind"       data
                    65 52 65 73 65 
                    6d 61 72 61 44

```

it could be useful to look for calls to those particular functions in the
native binary when they are obfuscated with this system.

but let's get to the juicy bits, let's search for resemara in the symbols
table and follow the code

```java
void ResemaraDetectionIdentifierRequest(ResemaraDetectionIdentifierRequest this,Listener p1)
{
  this.<init>();
  this.mListener = p1;
  return;
}

ResemaraDetectionIdentifierRequest getResemaraDetectionId(Listener p0)
{
  ResemaraDetectionIdentifierRequest local_0;
  
  local_0 = new ResemaraDetectionIdentifierRequest(p0);
  local_0.createResemaraDetectionId();
  return local_0;
}

void createResemaraDetectionId(ResemaraDetectionIdentifierRequest this)
{
  Thread local_0;
  Runnable ref;

  ref = new Runnable(this);
  local_0 = new Thread(ref);
  local_0.start();
  return;
}

void run(ResemaraDetectionIdentifierRequest$1 this)
{
  Context ref;
  AdvertisingIdClient$Info ref_00;
  String pSVar1;
  String pSVar2;
  Activity local_0;
  ResemaraDetectionIdentifierRequest pRVar3;
  StringBuilder ref_01;

  local_0 = UnityPlayer.currentActivity;
  ref = local_0.getApplicationContext();
  ref_00 = AdvertisingIdClient.getAdvertisingIdInfo(ref);
  pSVar1 = ref_00.getId();
  local_0 = UnityPlayer.currentActivity;
  ref = local_0.getApplicationContext();
  pSVar2 = ref.getPackageName();
  pRVar3 = this.this$0;
  ref_01 = new StringBuilder();
  ref_01.append(pSVar1);
  ref_01.append(pSVar2);
  pSVar1 = ref_01.toString();
  pSVar1 = ResemaraDetectionIdentifierRequest.access$000(pRVar3,pSVar1);
  if (pSVar1 == "") {
    ResemaraDetectionIdentifierRequest.access$100
              (this.this$0,"",ResemaraDetectionIdResultKind.Failed);
  }
  else {
    ResemaraDetectionIdentifierRequest.access$100
              (this.this$0,pSVar1,ResemaraDetectionIdResultKind.Succeeded);
  }
  return;
}

String access$000(ResemaraDetectionIdentifierRequest p0,String p1)
{
  String pSVar1;

  pSVar1 = p0.md5(p1);
  return pSVar1;
}

void access$100(ResemaraDetectionIdentifierRequest p0,String p1,ResemaraDetectionIdResultKind p2)

{
  p0.sendMessage(p1,p2);
  return;
}

void sendMessage(ResemaraDetectionIdentifierRequest this,String p1,ResemaraDetectionIdResultKind p2)
{
  int iVar1;
  Listener ref;

  if (this.mListener != null) {
    ref = this.mListener;
    iVar1 = p2.getKindInt();
    ref.onReceived(p1,iVar1);
  }
  return;
}

String md5(ResemaraDetectionIdentifierRequest this,String p1)
{
  MessageDigest ref;
  byte[] pbVar1;
  String ref_00;
  int iVar2;
  BigInteger ref_01;
  StringBuilder ref_02;

  ref = MessageDigest.getInstance("MD5");
  ref.reset();
  pbVar1 = p1.getBytes("UTF-8");
  ref.update(pbVar1);
  pbVar1 = ref.digest();
  ref_01 = new BigInteger(1,pbVar1);
  ref_00 = ref_01.toString(0x10);
  while (iVar2 = ref_00.length(), iVar2 < 0x20) {
    ref_02 = new StringBuilder();
    ref_02.append("0");
    ref_02.append(ref_00);
    ref_00 = ref_02.toString();
  }
  return ref_00;
}
```

okay, so it's just cramming a bunch of info into a string which is then
turned into a md5 hash and right-padded with zeros to 0x20 characters.
shouldn't be too hard to emulate if needed

to be continued...
