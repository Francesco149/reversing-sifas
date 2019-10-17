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

back to the native code. I keep searching for startup in the symbols table
and eventually notice a class named ```DotUnder.SVAPI.Startup```. looking
for references to this brings me to this function

```c
void DMHttpApi.__c__DisplayClass14_2$$_Login_b__3(int param_1,undefined4 param_2)

{
  int svapi;
  int response;
  
  if (DAT_037033e4 == '\0') {
    FUN_008722e4(0xb485);
    DAT_037033e4 = '\x01';
  }
  svapi = Instantiate1(Class$DotUnder.SVAPI.Startup);
  Startup$$.ctor(svapi,0);
  response = *(int *)(param_1 + 0x10);
  if (response == 0) {
    response = Instantiate1(Class$Action_StartupResponse_);
    FUN_023a2ed4(response,param_1,Method$DMHttpApi.__c__DisplayClass14_2._Login_b__4(),
                 Method$Action_StartupResponse_..ctor());
    *(int *)(param_1 + 0x10) = response;
  }
  if (svapi == 0) {
    ThrowException(0);
  }
  RuleNoAuth$$Send(svapi,param_2,response,Method$RuleNoAuth_StartupRequest_-StartupResponse_.Send())
  ;
  return;
}
```

it seems that this SVAPI class is responsible for constructing the API
calls. let's search for it

tracking down the methods is tricky, it seems that all the methods
are called indirectly, maybe virtual methods?

```c
void RuleNoAuth$$Send(int svapi,undefined4 param_2,undefined4 param_3,int method)

{
  code **ppcVar1;
  
  if (svapi == 0) {
    ThrowException(0);
  }
  ppcVar1 = (code **)**(code ***)(*(int *)(method + 0xc) + 0x60);
  (**ppcVar1)(svapi,param_2,param_3,1,1,ppcVar1);
  return;
}
```

dead end for now, we will maybe come back to this later, let's scroll
around some more in the DisplayClass14 methods which all seem to relate to
the login/auth process

the PublicEncrypt method is a simple call to the standard c# encryption lib

```
void DMCryptography$$PublicEncrypt(undefined4 param_1)

{
  int provider;

  if (DAT_037033cb == '\0') {
    FUN_008722e4(0x2bc6);
    DAT_037033cb = '\x01';
  }
  if (((Class$DotUnder.DMCryptography->BitField1 & 2) != 0) &&
     (Class$DotUnder.DMCryptography->Unk1 == 0)) {
    FUN_0087fd40();
  }
  provider = *(int *)&Class$DotUnder.DMCryptography->Instance->field_0x4;
  if (provider == 0) {
    ThrowException(0);
  }
  RSACryptoServiceProvider$$Encrypt(provider,param_1,1,0);
  return;
}
```

this is also familiar, old SIF used public key encryption and a random
string of bytes too

if we look at the msdn documentation we find that the overloads for Encrypt
are:

* `Encrypt(Byte[], Boolean)` Encrypts data with the RSA algorithm.
* `Encrypt(Byte[], RSAEncryptionPadding)` Encrypts data with the RSA
  algorithm using the specified padding.

in our case, it's using the first overload and the last zero parameter is
either incorrect decompilation or additional stuff generated by il2cpp

this function also tells us that offset 0x4 of DMCryptography is the
RSACryptoServiceProvider instance

key size is 1024:

```c
int * DMCryptography$$CreateRSAProvider(void)

{
  int *provider;

  if (DAT_037033d0 == '\0') {
    FUN_008722e4(0x2bc4);
    DAT_037033d0 = '\x01';
  }
  provider = (int *)Instantiate1(Class$System.Security.Cryptography.RSACryptoServiceProvider);
  RSACryptoServiceProvider$$.ctor(provider,0x400,0);
  if (provider == (int *)0x0) {
    ThrowException(0);
  }
  (**(code **)(*provider + 0x118))(provider,rsaKey,*(undefined4 *)(*provider + 0x11c));
  return provider;
}
```

the public rsa key is:

```
<RSAKeyValue><Modulus>v2VElqvCwrhdiXJRKerrlvfsnXS0L29uNtPhfK8SBfPludwYhfIPZupwhE3UcO0VZ8zQAXrzJ3Qgkw+qEOmtsNEKaCnk9uue/FAlrRqe+DRoNkNnx2BTAIU8rVZOPKjuFYgjd7JxbNAFEVNOp4jPfDCHBFJ4/b4+pDgZThr+CVk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

DMCryptography's constructors tells me that the field i previously named
Unk1 is an instance of RNGCryptoServiceProvider

```c
void DMCryptography$$.cctor(void)

{
  void *rngProvider;
  undefined4 provider;

  if (DAT_037033d1 == '\0') {
    FUN_008722e4(0x2bcb);
    DAT_037033d1 = '\x01';
  }
  rngProvider = (void *)Instantiate1(Class$System.Security.Cryptography.RNGCryptoServiceProvider);
  RNGCryptoServiceProvider$$.ctor(rngProvider,0);
  Class$DotUnder.DMCryptography->Instance->Unk1 = rngProvider;
  provider = DMCryptography$$CreateRSAProvider();
  *(undefined4 *)&Class$DotUnder.DMCryptography->Instance->rsaCryptoServiceProvider = provider;
  return;
}
```

if we take a look at the CallMain method we find yet another piece of the
puzzle. finally we get to construct the raw http request. it's a bit hard
to read where it works with 64-bit integers (userId and time) but.
I cleaned up and renamed everything

i renamed the string literal references to their contents for readability

```c
void DMHttpApi$$Call(Array *path,Array *body,undefined4 displayClass13_0xc,byte displayClass13_0x8,
                    undefined displayClass13_0x18,Array *mv)

{
  int displayClass13;
  undefined4 tmpClass;
  Array *requestId;
  undefined4 pathWithQuery;
  int hasUserId;
  int hasValue;
  ushort httpApi_0xbe;
  undefined4 byteAction;
  undefined4 callErrorAction;
  DMHttpApi *httpApi;
  uint uDisplayClass13_0x8;
  int isGuarded;
  byte *pDisplayClass13_0x8;
  undefined8 milliTimestamp;
  int64_t tmpValue;
  undefined8 objMilliTimestamp;
  undefined8 uStack56;
  byte bDisplayClass13_0x8;
  
  if (DAT_037033d4 == '\0') {
    FUN_008722e4(0x2bce);
    DAT_037033d4 = '\x01';
  }
  objMilliTimestamp = 0;
  uStack56 = 0;
  displayClass13 = Instantiate1(Class$DMHttpApi.__c__DisplayClass13_0);
  Object$$.ctor(displayClass13,0);
  if (displayClass13 == 0) {
    ThrowException(0);
    pDisplayClass13_0x8 = &DAT_00000008;
    DAT_00000008 = displayClass13_0x8;
    ThrowException(0);
    _DAT_0000000c = displayClass13_0xc;
    ThrowException(0);
  }
  else {
    pDisplayClass13_0x8 = (byte *)(displayClass13 + 8);
    *pDisplayClass13_0x8 = displayClass13_0x8;
    *(undefined4 *)(displayClass13 + 0xc) = displayClass13_0xc;
  }
  *(undefined *)(displayClass13 + 0x18) = displayClass13_0x18;
  pathWithQuery = "a";
  tmpClass = Time$$get_realtimeSinceStartup(0);
  if (displayClass13 == 0) {
    ThrowException(0);
  }
  *(undefined4 *)(displayClass13 + 0x10) = tmpClass;
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  requestId = DMHttpApi$$CreateRequestId();
  if (mv == (Array *)0x0) {
    pathWithQuery = String$$Format("?p={0}&id=",pathWithQuery,0);
  }
  else {
    pathWithQuery = String$$Format("?p={0}&mv={1}&id=",pathWithQuery,mv,0);
  }
  pathWithQuery = String$$Concat(path,pathWithQuery,0);
  pathWithQuery = String$$Concat(pathWithQuery,requestId,0);
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  hasUserId = FUN_021f760c(Class$DotUnder.DMHttpApi->Instance,Method$Nullable_int_.get_HasValue());
  if (hasUserId == 1) {
    if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
      FUN_0087fd40();
    }
    tmpValue._0_4_ =
         FUN_021f7614(Class$DotUnder.DMHttpApi->Instance,Method$Nullable_int_.get_Value());
    tmpClass = FUN_008ae744(Class$int,&tmpValue);
    tmpClass = String$$Format("&u={0}",tmpClass,0);
    pathWithQuery = String$$Concat(pathWithQuery,tmpClass,0);
  }
  Clock$$get_MilliTimestamp(&tmpValue,0);
  objMilliTimestamp = CONCAT44(tmpValue._4_4_,(undefined4)tmpValue);
  hasValue = FUN_021f8058(&objMilliTimestamp,Method$Nullable_long_.get_HasValue());
  milliTimestamp = CONCAT44((undefined4)tmpValue,tmpValue._4_4_);
  if (hasValue == 1) {
    milliTimestamp = FUN_021f8060(&objMilliTimestamp,Method$Nullable_long_.get_Value());
    tmpClass = FUN_008ae744(Class$long,&tmpValue);
    tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
    tmpValue._4_4_ = (undefined4)milliTimestamp;
    tmpClass = String$$Format("&t={0}",tmpClass,0);
    tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
    tmpValue._4_4_ = (undefined4)milliTimestamp;
    pathWithQuery = String$$Concat(pathWithQuery,tmpClass,0);
    tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
    tmpValue._4_4_ = (undefined4)milliTimestamp;
  }
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
    tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
    tmpValue._4_4_ = (undefined4)milliTimestamp;
  }
  tmpClass = DMHttpApi$$MakeRequestData(pathWithQuery,body);
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  bDisplayClass13_0x8 = *pDisplayClass13_0x8;
  uDisplayClass13_0x8 = (uint)bDisplayClass13_0x8;
  if (((*(byte *)(Class$DotUnder.HttpSubject + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.HttpSubject + 0x70) == 0)) {
    FUN_0087fd40();
    tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
    tmpValue._4_4_ = (undefined4)milliTimestamp;
  }
  if (bDisplayClass13_0x8 != 0) {
    uDisplayClass13_0x8 = 1;
  }
  HttpSubject$$OnStart(uDisplayClass13_0x8);
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  if (*pDisplayClass13_0x8 != 0) {
    httpApi_0xbe = *(ushort *)&Class$DotUnder.DMHttpApi->field_0xbe;
    if (((httpApi_0xbe & 0x200) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
      FUN_0087fd40();
      tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
      tmpValue._4_4_ = (undefined4)milliTimestamp;
      httpApi_0xbe = *(ushort *)&Class$DotUnder.DMHttpApi->field_0xbe;
    }
    httpApi = Class$DotUnder.DMHttpApi->Instance;
    isGuarded = httpApi->IsGuarded;
    if (isGuarded != 0) {
      if (((httpApi_0xbe & 0x200) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
        FUN_0087fd40();
        tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
        tmpValue._4_4_ = (undefined4)milliTimestamp;
        isGuarded = Class$DotUnder.DMHttpApi->Instance->IsGuarded;
      }
      if (((*(byte *)(Class$DotUnder.HttpSubject + 0xbf) & 2) != 0) &&
         (*(int *)(Class$DotUnder.HttpSubject + 0x70) == 0)) {
        FUN_0087fd40();
        tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
        tmpValue._4_4_ = (undefined4)milliTimestamp;
      }
      HttpSubject$$OnDuplex(isGuarded,path);
      tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
      tmpValue._4_4_ = (undefined4)milliTimestamp;
      return;
    }
    if (((httpApi_0xbe & 0x200) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
      FUN_0087fd40();
      tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
      tmpValue._4_4_ = (undefined4)milliTimestamp;
      httpApi = Class$DotUnder.DMHttpApi->Instance;
    }
    *(Array **)&httpApi->IsGuarded = path;
  }
  *(undefined4 *)(displayClass13 + 0x1c) = 0;
  *(undefined4 *)(displayClass13 + 0x14) = 0;
  byteAction = Instantiate1(Class$Action_byte[]_);
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  FUN_023a2ed4(byteAction,displayClass13,_Method$DMHttpApi.__c__DisplayClass13_0._Call_b(void),
               Method$Action_byte[]_..ctor());
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  callErrorAction =
       Instantiate1(Class$Action_DMHttpApi.CallError_-int_-HttpSubject.MessageObject_-Action_);
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  Action$$.ctor(callErrorAction,displayClass13,Method$DMHttpApi.__c__DisplayClass13_0._Call_b__1(),
                Method$Action_DMHttpApi.CallError_-int_-HttpSubject.MessageObject_-Action_..ctor());
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
    tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
    tmpValue._4_4_ = (undefined4)milliTimestamp;
  }
  DMHttpApi$$CallMain(pathWithQuery,tmpClass,byteAction,callErrorAction);
  tmpValue._0_4_ = (undefined4)((ulonglong)milliTimestamp >> 0x20);
  tmpValue._4_4_ = (undefined4)milliTimestamp;
  return;
}
```

here we can see how it constructs the url, which can contain these query
params

* p: always seems to be "a". maybe short for platform = android and
  hardcoded at compile time?
* mv (optional): not sure yet, it's passed to the function
* id: always 0?
* u (optional): the user id, stored in the httpapi instance

we already looked at MakeRequestData earlier and how it uses a sha1 hash
from CalcDigest, but now we know that the first 2 params passed to
CalcDigest are the url path and the request body

```c
Array * DMHttpApi$$MakeRequestData(Array *pathWithQuery,Array *body)

{
  System.Text.Encoding *utf8;
  Array *digest;
  Array *digest_;
  Array *digestBytes;
  undefined4 uVar1;
  int len;
  uint digestLength;

  if (DAT_037033dc == '\0') {
    FUN_008722e4(0x2bd4);
    DAT_037033dc = '\x01';
  }
  utf8 = Encoding$$get_UTF8((System.Text.Encoding *)0x0);
  if (body == (Array *)0x0) {
    ThrowException(0);
  }
  if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
    FUN_0087fd40();
  }
  digest = DMHttpApi$$CalcDigest(pathWithQuery,body,0,body->Length);
  if (utf8 == (System.Text.Encoding *)0x0) {
    ThrowException(0);
  }
                    /* probably a GetBytes call */
  digest_ = (Array *)(*utf8->vtable->DoSomething)(utf8,digest,utf8->vtable->SomePredicateFunc);
  if (digest_ == (Array *)0x0) {
    ThrowException(0);
  }
  digestBytes = (Array *)Instantiate(Class$byte[],body->Length + digest_->Length + 5);
  if (digestBytes == (Array *)0x0) {
    ThrowException(0);
  }
  if (digestBytes->Length == 0) {
    uVar1 = FUN_0089ec04();
    ThrowSomeOtherException(uVar1,0,0);
  }
  digestBytes->Data[0] = '[';
  Array$$CopyTo(body,digestBytes,1,0);
  len = body->Length;
  if ((uint)digestBytes->Length <= len + 1U) {
    uVar1 = FUN_0089ec04();
    ThrowSomeOtherException(uVar1,0,0);
  }
  digestBytes->Data[len + 1] = ',';
  len = body->Length;
  if ((uint)digestBytes->Length <= len + 2U) {
    uVar1 = FUN_0089ec04();
    ThrowSomeOtherException(uVar1,0,0);
  }
  digestBytes->Data[len + 2] = '\"';
  Array$$CopyTo(digest_,digestBytes,body->Length + 3,0);
  digestLength = digestBytes->Length;
  if (digestLength < 2) {
    uVar1 = FUN_0089ec04();
    ThrowSomeOtherException(uVar1,0,0);
  }
                    /* Data[digestLength - 2] = '"' */
  *(undefined *)((int)&digestBytes->Length + digestLength + 2) = 0x22;
  len = digestBytes->Length;
  if (len == 0) {
    uVar1 = FUN_0089ec04();
    ThrowSomeOtherException(uVar1,0,0);
  }
                    /* Data[digestLength - 1] = ']' */
  *(undefined *)((int)&digestBytes->Length + len + 3) = 0x5d;
  return digestBytes;
}
```

from here we know what the raw request body looks like this:


```
[request body,"hash"]
```

the request body is probably a json object

now I want to look around HttpSubject to see if we can figure out what
http headers it's using

from a quick look at OnStart it appears that the parameter passed to it is
a simple boolean to skip the CreateGuard call

```c
void HttpSubject$$OnStart(bool createGuardObject)

{
  if (DAT_037033fa == '\0') {
    FUN_008722e4(0x4f22);
    DAT_037033fa = '\x01';
  }
  if (createGuardObject != true) {
    return;
  }
  if (((*(byte *)(Class$DotUnder.HttpSubject + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.HttpSubject + 0x70) == 0)) {
    FUN_0087fd40();
  }
  HttpSubject$$CreateGuardObject();
  return;
}
```

ok, after taking a look around the other HttpSubject methods it seems that
this has more to do with displaying the loading screen than sending the
request. let's look at ```Network$$PostJson``` instead

```c
void Network$$PostJson(Array *url,Array *json,undefined4 response)
{
  if (DAT_036ffb92 == '\0') {
    FUN_008722e4(0x70b4);
    DAT_036ffb92 = '\x01';
  }
  if (((*(byte *)(Class$DotUnder.NetworkAndroid + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.NetworkAndroid + 0x70) == 0)) {
    FUN_0087fd40();
  }
  NetworkAndroid$$PostJson(url,json,response);
  return;
}

undefined4 NetworkAndroid$$PostJson(Array *url,Array *json,undefined4 response)

{
  int proxy;
  undefined4 proxyAddress;
  int proxyHasAddress;
  int *params;
  int iVar1;
  undefined4 uVar2;
  int proxyHost;
  undefined4 uStack80;
  undefined4 proxyPort;
  undefined8 guid;
  undefined8 uStack64;
  undefined8 guid_;
  undefined8 uStack48;

  if (DAT_036ffb98 == '\0') {
    FUN_008722e4(0x7097);
    DAT_036ffb98 = '\x01';
  }
  guid_ = 0;
  uStack48 = 0;
  if (((*(byte *)(Class$DotUnder.NetworkAndroid + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.NetworkAndroid + 0x70) == 0)) {
    FUN_0087fd40();
  }
  NetworkAndroid$$Initialize();
  proxyPort = 0;
  proxy = Config$$get_Proxy(0);
  if (proxy == 0) {
    proxyHost = 0;
  }
  else {
    proxyPort = 0;
    proxyAddress = WebProxy$$get_Address(proxy,0);
    if (((*(byte *)(Class$System.Uri + 0xbf) & 2) != 0) && (*(int *)(Class$System.Uri + 0x70) == 0))
    {
      FUN_0087fd40();
    }
    proxyHasAddress = Uri$$op_Inequality(proxyAddress,0,0);
    proxyHost = 0;
    if (proxyHasAddress == 1) {
      proxyHost = WebProxy$$get_Address(proxy,0);
      if (proxyHost == 0) {
        ThrowException(0);
      }
      proxyHost = Uri$$get_Host(proxyHost,0);
      proxy = WebProxy$$get_Address(proxy,0);
      if (proxy == 0) {
        ThrowException(0);
      }
      proxyPort = Uri$$get_Port(proxy,0);
    }
  }
  if (((*(byte *)(Class$System.Guid + 0xbf) & 2) != 0) && (*(int *)(Class$System.Guid + 0x70) == 0))
  {
    FUN_0087fd40();
  }
  Guid$$NewGuid(&guid,0);
  guid_ = guid;
  uStack48 = uStack64;
  proxy = Guid$$ToString(&guid_,0);
  proxyAddress = Instantiate1(Class$Network.Connection);
  Network.Connection$$.ctor(proxyAddress,proxy,response);
  if (((*(byte *)(Class$DotUnder.NetworkAndroid + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.NetworkAndroid + 0x70) == 0)) {
    FUN_0087fd40();
  }
  proxyHasAddress = *(int *)(*(int *)(Class$DotUnder.NetworkAndroid + 0x5c) + 8);
  if (proxyHasAddress == 0) {
    ThrowException(0);
  }
  FUN_0237432c(proxyHasAddress,proxy,proxyAddress,
               Method$Dictionary_string_-Network.Connection_.Add());
  params = (int *)Instantiate(Class$object[],7);
  proxyHasAddress = *(int *)(*(int *)(Class$DotUnder.NetworkAndroid + 0x5c) + 4);
  if (params == (int *)0x0) {
    ThrowException(0);
  }
  if ((proxyHasAddress != 0) &&
     (iVar1 = FUN_008aea80(proxyHasAddress,*(undefined4 *)(*params + 0x20)), iVar1 == 0)) {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if (params[3] == 0) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  params[4] = proxyHasAddress;
  if ((proxy != 0) &&
     (proxyHasAddress = FUN_008aea80(proxy,*(undefined4 *)(*params + 0x20)), proxyHasAddress == 0))
  {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if ((uint)params[3] < 2) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  params[5] = proxy;
  if ((url != (Array *)0x0) &&
     (proxy = FUN_008aea80(url,*(undefined4 *)(*params + 0x20)), proxy == 0)) {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if ((uint)params[3] < 3) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  *(Array **)(params + 6) = url;
  if ((json != (Array *)0x0) &&
     (proxy = FUN_008aea80(json,*(undefined4 *)(*params + 0x20)), proxy == 0)) {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if ((uint)params[3] < 4) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  *(Array **)(params + 7) = json;
  if ((proxyHost != 0) &&
     (proxy = FUN_008aea80(proxyHost,*(undefined4 *)(*params + 0x20)), proxy == 0)) {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if ((uint)params[3] < 5) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  params[8] = proxyHost;
  proxy = FUN_008ae744(Class$int,&proxyPort);
  if ((proxy != 0) &&
     (proxyHost = FUN_008aea80(proxy,*(undefined4 *)(*params + 0x20)), proxyHost == 0)) {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if ((uint)params[3] < 6) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  params[9] = proxy;
  uStack80 = 10;
  proxy = FUN_008ae744(Class$int,&uStack80);
  if ((proxy != 0) &&
     (proxyHost = FUN_008aea80(proxy,*(undefined4 *)(*params + 0x20)), proxyHost == 0)) {
    uVar2 = FUN_0089f30c();
    ThrowSomeOtherException(uVar2,0,0);
  }
  if ((uint)params[3] < 7) {
    uVar2 = FUN_0089ec04();
    ThrowSomeOtherException(uVar2,0,0);
  }
  params[10] = proxy;
  NetworkAndroid$$CallStaticOnMainThread("postJson",params);
  return proxyAddress;
}
```

this seems lengthy, but it's mainly because it's calling into java

the first part checks if a proxy is set and extracts host and port. then it
generates a guid and reuses the proxy temp vars for the stringified guid
and the connection, which is a bit confusing. the only proxy information
that is retained is proxyHost and proxyPort.

the `Guid$$ToString` call wasn't originally named. i figured out what it
was by googling strings used inside the function and finding it in
microsoft's dotnet github repo

it seems that network connections are identified by a guid. it's probably
android stuff we don't care about

next, an array of generic objects is created and all the info previously
retrieved is packed into it. this data is then passed to java and postJson
is called

time to go back to java code

I think we're finally at the end of the chain for http requests, it's using
OkHttp, an open source library, under the hood:

```java
void postJson(PostJson this,NetworkListener p1,String p2,String p3,byte[] p4,String p5,int p6,int p7
             )

{
  OkHttpClient$Builder ref;
  int iVar1;
  MediaType contentType;
  RequestBody pRVar2;
  Request pRVar3;
  Call ref_00;
  OkHttpClient local_0;
  Proxy ref_01;
  Proxy$Type pPVar4;
  SocketAddress ref_02;
  Map ref_03;
  Callback ref_04;
  Request$Builder ref_05;
  
  local_0 = this.mHttpClient;
  ref = local_0.newBuilder();
  ref = ref.connectTimeout((long)p7 & -0x100000000 | ZEXT48(p7),TimeUnit.SECONDS);
  ref = ref.readTimeout((long)p7,TimeUnit.SECONDS);
  ref = ref.writeTimeout((long)p7,TimeUnit.SECONDS);
  if ((p5 != null) && (iVar1 = p5.length(), 0 < iVar1)) {
    pPVar4 = Proxy$Type.HTTP;
    ref_02 = new SocketAddress(p5,p6);
    ref_01 = new Proxy(pPVar4,ref_02);
    ref = ref.proxy(ref_01);
  }
  local_0 = ref.build();
  contentType = MediaType.parse("application/json");
  pRVar2 = PostJsonRequestBody.create(contentType,p4);
  ref_05 = new Request$Builder();
  ref_05 = ref_05.url(p3);
  ref_05 = ref_05.post(pRVar2);
  pRVar3 = ref_05.build();
  ref_00 = local_0.newCall(pRVar3);
  ref_03 = this.mRequestList;
  ref_03.put(p2,ref_00);
  ref_04 = new Callback(this,p2,p1);
  ref_00.enqueue(ref_04);
  return;
}
```

we can easily figure out that p4 is offset: https://github.com/square/okhttp/blob/c4f338ec172411975c9c0f05c7f48fc1b3dca715/okhttp/src/main/java/okhttp3/RequestBody.kt#L131

from the part where it uses SocketAddress, which is documented [here](https://docs.oracle.com/javase/7/docs/api/java/net/InetSocketAddress.html)
we can figure out that p5 and p6 are addr and port for the proxy

in the last part it adds the request to a map called mRequestList. p2
appears to be the string key that identifies this request

then it enqueues the request with a custom callback. if we look at the
PostJsonCallback constructor we have names for all the parameters:

```
void PostJson$PostJsonCallback
               (PostJson$PostJsonCallback this,PostJson p1,String p2,NetworkListener p3)

{
  this.this$0 = p1;
  this.<init>();
  this.taskId = p2;
  this.listener = p3;
  return;
}
```

this confirms that the map key is taskId

here is postJson again, but now we've named everything:

```java
void postJson(PostJson this,NetworkListener listener,String taskId,String url,byte[] body,
             String proxyAddr,int proxyPort,int timeout)

{
  OkHttpClient$Builder clientBuilder;
  int proxyAddrLen;
  MediaType contentType;
  RequestBody body;
  Request request;
  Call call;
  OkHttpClient httpClient;
  Proxy proxy;
  Proxy$Type proxyType;
  SocketAddress proxySocketAddress;
  Map requests;
  Callback callback;
  Request$Builder requestBuilder;

  httpClient = this.mHttpClient;
  clientBuilder = httpClient.newBuilder();
  clientBuilder =
       clientBuilder.connectTimeout((long)timeout & -0x100000000 | ZEXT48(timeout),TimeUnit.SECONDS)
  ;
  clientBuilder = clientBuilder.readTimeout((long)timeout,TimeUnit.SECONDS);
  clientBuilder = clientBuilder.writeTimeout((long)timeout,TimeUnit.SECONDS);
  if ((proxyAddr != null) && (proxyAddrLen = proxyAddr.length(), 0 < proxyAddrLen)) {
    proxyType = Proxy$Type.HTTP;
    proxySocketAddress = new SocketAddress(proxyAddr,proxyPort);
    proxy = new Proxy(proxyType,proxySocketAddress);
    clientBuilder = clientBuilder.proxy(proxy);
  }
  httpClient = clientBuilder.build();
  contentType = MediaType.parse("application/json");
  body = PostJsonRequestBody.create(contentType,body);
  requestBuilder = new Request$Builder();
  requestBuilder = requestBuilder.url(url);
  requestBuilder = requestBuilder.post(body);
  request = requestBuilder.build();
  call = httpClient.newCall(request);
  requests = this.mRequestList;
  requests.put(taskId,call);
  callback = new Callback(this,taskId,listener);
  call.enqueue(callback);
  return;
}
```

so it seems that there aren't any particular headers we should be aware of.
I guess everything is packed in the json object

so let's take the startup request for example. we can figure out what to
send by looking at `Serialization$$SerializeStartupRequest`

the json body will be something like:

```json
{"mask":"blahblah","resemara_detection_identifier":"123abc","time_difference":123}
```

and by looking at `Serialization$$DeserializeStartupResponse` we can figure
out that we will receive something like:

```json
{"user_id":123,"authorization_key":"123abc"}
```

of course this will all be wrapped in that json array with the hash we
analyzed earlier

but what is "mask" ? let's take another look at `DMHttpApi$$Login`

```c
  UserKey$$GetID(&userId,0);
  password = UserKey$$GetPW(0);
  iUserId = FUN_021f760c(&userId,Method$Nullable_int_.get_HasValue());
  if (password == 0 || iUserId == 0) {
    password = Instantiate1(Class$DMHttpApi.__c__DisplayClass14_2);
    Object$$.ctor(password,0);
    if (password == 0) {
      ThrowException(0);
    }
    *(int *)(password + 0xc) = iVar1;
    if (((Class$DotUnder.DMCryptography->BitField1 & 2) != 0) &&
       (Class$DotUnder.DMCryptography->Unk1 == 0)) {
      FUN_0087fd40();
    }
    data = (Array *)DMCryptography$$RandomBytes(0x20);
    *(Array **)(password + 8) = data;
    mask = DMCryptography$$PublicEncrypt(data);
    if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
       (*(int *)(Class$System.Convert + 0x70) == 0)) {
      FUN_0087fd40();
    }
    mask = Convert$$ToBase64String(mask,0);
    data = (Array *)Config$$get_StartupKey(0);
    if (((Class$DotUnder.DMHttpApi->BitField1 & 2) != 0) && (Class$DotUnder.DMHttpApi->Unk1 == 0)) {
      FUN_0087fd40();
    }
    Class$DotUnder.DMHttpApi->Instance->SessionKey = data;
    uVar2 = Instantiate1(Class$Action_StartupRequest_);
    FUN_023a2ed4(uVar2,password,Method$DMHttpApi.__c__DisplayClass14_2._Login_b__3(),
                 Method$Action_StartupRequest_..ctor());
    StartupRequestBuilder$$Create(mask,uVar2,0);
  }
```

this is essentially the part where it checks if we have an account, and if
we don't it creates a new one

again this is confusing because it's reusing variables for multiple things
but as you can see i was able to figure out that the first param of
`StartupRequestBuilder$$Create` is mask by mapping out the struct with
getters/setters as explained before, and it's generated by encrypting
random bytes with the public key we saw before and then encoding it as
base64

we can also see that it's setting the initial SessionKey to the StartupKey
which as seen earlier is `i0qzc6XbhFfAxjN2`

to be continued...
