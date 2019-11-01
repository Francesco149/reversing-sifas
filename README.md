this is a collection of info about love live all stars' internals that I
collect and add as I reverse engineer it

this information is public domain. feel free to use it and republish it
however you please

# road to headless client
this is a raw diary of notes i wrote down as I reverse engineered the game
from scratch. the goal was to create a headless client that could connect
to the game servers, create accounts and get daily login rewards. this is
completely uncut, and there will be wrong premature observations that are
later corrected

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

note: these values change with every update, they already changed as I
wrote these notes, but they're pretty easy to find anyway.

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

this is a good time to try and MITM the http requests that are actually
sent to see if we're right. we need root to bypass ssl pinning

I used this guide to install magisk and hide root on android x86
https://asdasd.page/2018/02/18/Install-Magisk-on-Android-x86/

which consists of
* copying kernel and ramdisk.img from the android partition to a linux
  machine
* `mkbootimg --kernel kernel --ramdisk ramdisk.img --output boot.img`
* copy boot.img back to android device
  `sudo cp boot.img /mnt/ssd/android-8.1-r2/data/media/0/Download/`
* patch boot.img with MagiskManager
* copy patched_boot.img back to linux
  `sudo cp /mnt/ssd/android-8.1-r2/data/media/0/Download/magisk_patched.img .`
* `abootimg -x magisk_patched.img`
* rename zImage to kernel and overwrite the one in android partition
* Rename initrd.img to ramdisk.img and overwrite in android partition

now magisk should be installed. enable magisk hide from the settings and
then from the magisk hide menu, toggle it on for love live

at this point i was planning to install riru and edxposed to then use
trustmealready to disable ssl pinning and be able to use a mitm proxy

unfortunately magisk was failing to mount some stuff and modules weren't
working. at least root is working and it's hidden from the game. we
can work with this. I could try the same thing i did with old sif which
was to write a library to inject and hook game functions to log requests

so the first thing i look for is a simple library with few exports that is
loaded after the game. `libKLab.NativeInput.Native.so` looks like a good
candidate. it looks like it's called from java and exports a handful of
`Java_com_klab*` functions which are probably the only ones we would need
to export to replace it.

the idea is, you replace the library, export the same functions, and under
the hood you load the original library and forward all calls to it while
you inject your own initialization into a function of your choice

the injected code in this case would hook MakeRequestData, redirecting it
to a function that calls the real MakeRequestData and prints the json
object to android's logcat

to avoid generating repetitive dlopen/dlsym code for each export which
would just make the binary larger for no good reason, I define the exports
to be just placeholder jmp's at compile time, then at runtime it goes
through the list of functions and replaces the placeholder jmps with jmps
to the original library

as a first test, I just make the stub library do absolutely nothing, just
to see if it works

we must also decide where to initialize our stub library. onInitialize
seems like a good candidate, as we can see from the disassembly it takes
a single param:

```c
void Java_com_klab_nativeinput_NativeInputJava_onInitialize(JNIEnv *env)

{
  jclass p_Var1;
  
  if (env != (JNIEnv *)0x0) {
    sJEnv = env;
    p_Var1 = (*env->functions->FindClass)(env,"com/klab/nativeinput/NativeInputJava");
    sJClass = (jclass)(*env->functions->NewGlobalRef)(env,(jobject)p_Var1);
                    /* WARNING: Could not recover jumptable at 0x00015ac2. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*sJEnv->functions->GetStaticMethodID)(sJEnv,sJClass,"NativeInputGetTimestamp","()D");
    return;
  }
  return;
}
```

so here's my hello world lib:

```c
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/sysconf.h>

#define log(x) __android_log_write(ANDROID_LOG_DEBUG, __FILE__, x);

#define java_func(func) \
    Java_com_klab_nativeinput_NativeInputJava_##func

#define exports(macro) \
  macro(java_func(clearTouch)) \
  macro(java_func(lock)) \
  macro(java_func(onFinalize)) \
  macro(java_func(stockDeviceButtons)) \
  macro(java_func(stockNativeTouch)) \
  macro(java_func(testOverrideFlgs)) \
  macro(java_func(unlock)) \

/*
  I decided to go with absolute jmp's. since arm doesn't allow 32-bit
  immediate jumps I have to place the address right after the jmp and
  reference it using [pc,#-4]. pc is 8 bytes after the current instruction,
  so #-4 reads 4 bytes after the current instruction.
  0xBAADF00D is then replaced by the correct address at runtime
*/

#define define_trampoline(name) \
void __attribute__((naked)) name() { \
    asm("ldr pc,[pc,#-4]"); \
    asm(".word 0xBAADF00D"); \
}

/* runs define_trampoline on all functions listed in exports */
exports(define_trampoline)

#define stringify_(x) #x
#define stringify(x) stringify_(x)
#define to_string_array(x) stringify(x),
static char* export_names[] = { exports(to_string_array) 0 };

void (*_onInitialize)(void* env);

/*
  make memory readadable, writable and executable. size is
  ceiled to a multiple of PAGESIZE and addr is aligned to
  PAGESIZE
*/
#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGEOF(addr) (void*)((int)(addr) & ~(PAGESIZE - 1))
#define PAGE_ROUND_UP(x) \
    ((((int)(x)) + PAGESIZE - 1) & (~(PAGESIZE - 1)))
#define munprotect(addr, n) \
    mprotect(PAGEOF(addr), PAGE_ROUND_UP(n), PROT_RWX)

static
void init() {
  char** s;
  void *original, *stub;
  log("hello from the stub library!");
  original = dlopen("libKLab.NativeInput.Native.so.bak", RTLD_LAZY);
  stub = dlopen("libKLab.NativeInput.Native.so", RTLD_LAZY);
  for (s = export_names; *s; ++s) {
    void** stub_func = dlsym(stub, *s);
    log(*s);
    munprotect(&stub_func[1], sizeof(void*));
    stub_func[1] = dlsym(original, *s);
  }
  *(void**)&_onInitialize =
    dlsym(original, stringify(java_func(onInitialize)));
}

void java_func(onInitialize)(void* env) {
  init();
  _onInitialize(env);
}
```

I build it with this script:

```sh
#!/bin/sh

CFLAGS="-fPIC -Wall $CFLAGS"
LDFLAGS="-shared -llog -ldl $LDFLAGS"
[ -z "$CC" ] &&
  echo "please set CC to your android toolchain compiler" && exit 1
$CC $CFLAGS sniffas.c $LDFLAGS -o libKLab.NativeInput.Native.so
```

remember to download the android standalone toolchain and point CC to it

```sh
export CC=~/android-ndk-r20/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang
./build.sh
```

then i copy it to android and replace the original library, making sure
to keep permissions

```sh
adb root
adb push libKLab.NativeInput.Native.so /data/app/
adb shell

cd /data/app/com.klab.lovelive.allstars-*/lib/arm/
mv libKLab.NativeInput.Native.so{,.bak}
mv /data/app/libKLab.NativeInput.Native.so .
chmod 755 libKLab.NativeInput.Native.so
chown system:system libKLab.NativeInput.Native.so
exit
```

and sure enough, if we start the game and look at logcat we see:

```
10-18 21:57:03.260 21620 21645 D sniffas.c: hello from the stub library!
10-18 21:57:03.260 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_clearTouch
10-18 21:57:03.260 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_lock
10-18 21:57:03.260 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_onFinalize
10-18 21:57:03.260 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_stockDeviceButtons
10-18 21:57:03.260 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_stockNativeTouch
10-18 21:57:03.261 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_testOverrideFlgs
10-18 21:57:03.261 21620 21645 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_unlock
```

and the game runs just fine

let's try to hook MakeRequestData now

first of all we need to know its relative address in memory, from where
il2cpp stars. just hover over the address in ghidra, you want the
"Imagebase Offset"

to get the address of the function in memory we can just add this offset
to the base address of il2cpp.so which we can obtain with `dladdr` and a
known export. I picked one at random from ghidra's list of exports

```c
  il2cpp = dlopen("libil2cpp.so", RTLD_LAZY);
  il2cpp_export = dlsym(il2cpp, "UnityAdsEngineInitialize");
  dladdr(il2cpp_export, &dli);
  sprintf(buf, "il2cpp at %p", dli.dli_fbase);
  log(buf);
```

you can go all fancy and dynamically search for the function's byte pattern
but for now I'm just gonna hardcode the address

let's print the first 8 bytes at MakeRequestData to check that we are
indeed getting the right address

```c
  /* log first 8 bytes at MakeRequestData to check that we got it right */
  p = buf;
  MakeRequestData = (char*)dli.dli_fbase + 0xEFCDDC;
  p += sprintf(p, "MakeRequestData at %p: ", MakeRequestData);
  for (i = 0; i < 8; ++i) {
    p += sprintf(p, "%02x ", MakeRequestData[i]);
  }
  log(buf);
```

sure enough, we get:

```
10-19 01:31:26.569 28198 28223 D sniffas.c: il2cpp at 0x8000000
10-19 01:31:26.569 28198 28223 D sniffas.c: MakeRequestData at 0x8efcddc: f0 48 2d e9 10 b0 8d e2 
```

which matches ghidra:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined DMHttpApi$$MakeRequestData()
             undefined         r0:1           <RETURN>
                             DMHttpApi$$MakeRequestData                      XREF[2]:     DMHttpApi$$Call:00f0cab0(c), 
                                                                                          034637e4(*)  
        00f0cddc f0 48 2d e9     stmdb      sp!,{ r4 r5 r6 r7 r11 lr }
        00f0cde0 10 b0 8d e2     add        r11,sp,#0x10
```

okay, let's define our hook function and a global function pointer we will
use to call the original function

```c
static void* (*original_MakeRequestData)(void* pathWithQuery, void* body);

static
void* hooked_MakeRequestData(void* pathWithQuery, void* body) {
  log("hello from MakeRequestData!");
  return original_MakeRequestData(pathWithQuery, body);
}
```

so, what exactly do we need to do to hook this function? it's actually
really simple. we overwrite the function's code with a jump to our own
function

the only tricky part is calling the original function, which we just
overwrote. the solution I use is to copy the original code somewhere else
and slap a jump that goes back to the original function, right after the
jump we wrote. some people call this a "trampoline".

to explain this more visually, this is how the code looks like before
hooking

```asm
MakeRequestData:
  stmdb      sp!,{ r4 r5 r6 r7 r11 lr }
  add        r11,sp,#0x10
  sub        sp,sp,#0x8
  cpy        r5,r0
  ...
```

 after hooking

```asm
original_MakeRequestData:
  stmdb      sp!,{ r4 r5 r6 r7 r11 lr }
  add        r11,sp,#0x10
  jmp MakeRequestData_continue

MakeRequestData:
  jmp hooked_MakeRequestData
MakeRequestData_continue:
  sub        sp,sp,#0x8
  cpy        r5,r0
  ...
```

the actual jump is not gonna look like that though, in ARM we need to do
a weird absolute jump you've seen in my initial stub library code

so let's implement this hook!

here's where I generate the trampoline

```c
  *(void**)&original_MakeRequestData = malloc(8 + 8);
  code = (unsigned*)original_MakeRequestData;
  munprotect(code, 8);
  memcpy(code, MakeRequestData, 8);
  code[2] = 0xE51FF004; /* ldr pc,[pc,#-4] */
  code[3] = (unsigned)MakeRequestData + 8;
```

and here's where I overwrite the original function's code

```c
  code = (unsigned*)MakeRequestData;
  munprotect(code, 8);
  code[0] = 0xE51FF004; /* ldr pc,[pc,#-4] */
  code[1] = (unsigned)hooked_MakeRequestData;
```

if we run this and check logcat after tapping the main menu and logging
into the game, we get:

```
10-19 01:52:19.220 28588 28613 D sniffas.c: hello from the stub library!
10-19 01:52:19.220 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_clearTouch
10-19 01:52:19.220 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_lock
10-19 01:52:19.221 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_onFinalize
10-19 01:52:19.221 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_stockDeviceButtons
10-19 01:52:19.221 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_stockNativeTouch
10-19 01:52:19.221 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_testOverrideFlgs
10-19 01:52:19.221 28588 28613 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_unlock
10-19 01:52:19.222 28588 28613 D sniffas.c: il2cpp at 0x8000000
10-19 01:52:19.222 28588 28613 D sniffas.c: MakeRequestData at 0x8efcddc: f0 48 2d e9 10 b0 8d e2 
10-19 01:52:40.523 28588 28613 D sniffas.c: hello from MakeRequestData!
10-19 01:52:42.410 28588 28613 D sniffas.c: hello from MakeRequestData!
10-19 01:52:47.239 28588 28613 D sniffas.c: hello from MakeRequestData!
```

the hard part is done! now we can simply log the request data. we already
know the key field offsets for C#'s Array struct

```c
typedef struct {
  char unknown[12];
  int Length;
  char data[1]; /* actually Length bytes */
} Array;

static
void Array_log_ascii(Array* arr) {
  char* buf = malloc(arr->Length + 1);
  memcpy(buf, arr->Data, arr->Length);
  buf[arr->Length] = 0;
  log(buf);
  free(buf);
}
```

however, pathWithQuery is most likely a String. let's reverse engineer the
String layout real quick. from String$$Copy we can instantly tell Length
is at offset 0x8 and data is at 0xC

```c
int String$$Copy(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  if (DAT_037078b1 == '\0') {
    FUN_008722e4(0x94b7);
    DAT_037078b1 = '\x01';
  }
  if (param_1 != 0) {
    iVar3 = *(int *)(param_1 + 8);
    iVar1 = thunk_FUN_008c05c4(iVar3);
    if (iVar1 == 0) {
      ThrowException(0);
    }
    Buffer$$Memcpy(iVar1 + 0xc,param_1 + 0xc,iVar3 << 1,0);
    return iVar1;
  }
  uVar2 = Instantiate1(Class$System.ArgumentNullException);
  ArgumentNullException$$.ctor(uVar2,"str",0);
  ThrowSomeOtherException(uVar2,0,Method$String.Copy());
  uVar2 = caseD_15();
  return uVar2;
}
```

here's our String struct

```c
typedef struct {
  char unknown[8];
  int Length;
  char data[1]; /* actually Length bytes */
} String;
```

we have another problem though, the default encoding for strings in .net
is UTF16LE. I'm just gonna truncate it to ascii for now and change data
to an array of unsigned short's

```c
typedef struct {
  char unknown[8];
  int Length;
  unsigned short Data[1];
} String;

/* truncate to ascii. good enough for now */
static
void String_log(String* str) {
  int i;
  char* buf = malloc(str->Length + 1);
  for (i = 0; i < str->Length; ++i) {
    buf[i] = (char)str->Data[i];
  }
  buf[str->Length] = 0;
  log(buf);
  free(buf);
}
```

update hook to log the requests:

```c
static
Array* (*original_MakeRequestData)(String* pathWithQuery, Array* body);

static
Array* hooked_MakeRequestData(String* pathWithQuery, Array* body) {
  Array* res;
  String_log(pathWithQuery);
  res = original_MakeRequestData(pathWithQuery, body);
  Array_log_ascii(res);
  return res;
}
```

let's start the game, tap the main screen, and...

```
10-19 02:50:00.968 31593 31618 D sniffas.c: hello from the stub library!
10-19 02:50:00.968 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_clearTouch
10-19 02:50:00.968 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_lock
10-19 02:50:00.969 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_onFinalize
10-19 02:50:00.969 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_stockDeviceButtons
10-19 02:50:00.969 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_stockNativeTouch
10-19 02:50:00.969 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_testOverrideFlgs
10-19 02:50:00.969 31593 31618 D sniffas.c: Java_com_klab_nativeinput_NativeInputJava_unlock
10-19 02:50:00.969 31593 31618 D sniffas.c: il2cpp at 0x8000000
10-19 02:50:00.969 31593 31618 D sniffas.c: MakeRequestData at 0x8efcddc: f0 48 2d e9 10 b0 8d e2 
10-19 02:50:21.240 31593 31618 D sniffas.c: /login/login?p=a&id=1&u=CENSORED_USER_ID
10-19 02:50:21.241 31593 31618 D sniffas.c: [{"user_id":CENSORED_USER_ID,"auth_count":CENSORED_AUTH_COUNT,"mask":"CENSORED_MASK","asset_state":"CENSORED_ASSET_STATE"},"CENSORED_HASH"]
10-19 02:50:22.850 31593 31618 D sniffas.c: /bootstrap/fetchBootstrap?p=a&mv=CENSORED_MV&id=2&u=CENSORED_USER_ID&t=CENSORED_TIME_1
10-19 02:50:22.850 31593 31618 D sniffas.c: [{"bootstrap_fetch_types":[2,3,4,5,9,10],"device_token":"CENSORED_DEVICE_TOKEN","device_name":"Censored device name"},"CENSORD_HASH_2"]
10-19 02:50:27.047 31593 31618 D sniffas.c: /notice/fetchNotice?p=a&mv=CENSORED_MV&id=3&u=CENSORED_USER_ID&t=CENSORED_TIME_2
10-19 02:50:27.047 31593 31618 D sniffas.c: [null,"CENSORED_HASH"]
```

hell yeah. I had to censor pretty much everything in the data but you get
the idea. it's how we predicted it

hooking MakeRequestData might've been a mistake though, we can't log the
response like this. let's hook `Network$$PostJson` instead. it has all
the same info we're logging now, plus the response.

this is where it constructs the response in CallMain

```c
  response = Instantiate1(Class$Action_Network.Response_);
  FUN_023a2ed4(response,displayClass20,Method$DMHttpApi.__c__DisplayClass20_0._CallMain_b__1(),
               Method$Action_Network.Response_..ctor());
  displayClass20 = Network$$PostJson(url,json,response);
```

a quick search for Network.Response yields the following fields

```c
undefined4 Network.Response$$get_Status(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}

undefined4 Network.Response$$get_Bytes(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}

uint Network.Response$$get_IsTimeout(int param_1)

{
  return (uint)*(byte *)(param_1 + 0x10);
}

uint Network.Response$$get_IsNetworkError(int param_1)

{
  return (uint)*(byte *)(param_1 + 0x11);
}

undefined4 Network.Response$$get_ErrorMessage(int param_1)

{
  return *(undefined4 *)(param_1 + 0x14);
}

```

I wasn't sure about the Bytes type so I looked around some more, found
this in postJsonCallback

```c
    uVar2 = AndroidJavaObject$$GetRawObject(piVar1,0);
    uVar2 = AndroidJNIHelper$$ConvertFromJNIArray
                      (uVar2,Method$AndroidJNIHelper.ConvertFromJNIArray()_byte[]_);
...
    iVar3 = Instantiate1(Class$Network.Response);
    Object$$.ctor(iVar3,0);
    *(undefined4 *)(iVar3 + 8) = param_3;
    *(undefined4 *)(iVar3 + 0xc) = uVar2;
    *(undefined *)(iVar3 + 0x11) = param_6;
    *(undefined *)(iVar3 + 0x10) = param_5;
    *(undefined4 *)(iVar3 + 0x14) = param_7;
```

it should be an array of bytes

now the tricky part is, it's actually receiving `Action<Network.Response>`,
not just the struct. this means that somewhere down the line, this action
gets invoked and the Response object we want is created

yeah, I guess we won't be able to log the response from here. we'll need
another hook

let's hook `Network.Response$$get_Bytes`. something is bound to call it
when a response is received

these are the hooks I ended up with

```c
typedef struct {
  char unknown[8];
  int Status;
  Array* Bytes;
  char isTimeout;
  char isNetworkError;
  String* ErrorMessage;
} Response;

static
void (*original_PostJson)(String* url, Array* body, void* delegate,
  void* unk);

static
void hooked_PostJson(String* url, Array* body, void* delegate, void* unk) {
  String_log(url);
  Array_log_ascii(body);
  original_PostJson(url, body, delegate, unk);
}

static
Array* (*original_get_Bytes)(Response* resp);

static
Array* hooked_get_Bytes(Response* resp) {
  char buf[512];
  sprintf(buf, "[%p] %p", __builtin_return_address(0), resp);
  log(buf);
  Array_log_ascii(resp->Bytes);
  return original_get_Bytes(resp);
}
```

and if we run now, we get:

![snifas logging requests](pic.png)

amazing! now we can see all traffic

you can check out the full stub library source code [here](https://github.com/Francesco149/sniffas)

some people would have used a mitm http proxy here, however the game is
very picky about it and most likely is ssl pinning, so this is much easier
for me and lets me log other info too, for example i can log where any
given function is called from, even with complicated indirect calls. you
just have to format and log `__builtin_return_address(0)` from the hook

let's try to put this all together and craft a startup request and see
what the server thinks of it.

first of all, this is how you reset your linked account and force the game
to create a new one. this is the equivalent of what is described here
https://www.reddit.com/r/SchoolIdolFestival/comments/da5g2x/how_to_reroll_sifas_without_deleting_the_whole/f1pe67m/
except it's all automatic

```sh
mv /data/data/com.klab.lovelive.allstars{,.bak}
pm clear com.klab.lovelive.allstars
mv /data/data/com.klab.lovelive.allstars{.bak,}
```

from the requests log it seems like it first prompts you to log with
a google id and then calls `/dataLink/fetchGameServiceDataBeforeLogin`
which either returns already linked data for that account or null, in
which case the game proceeds with the startup request to create a new
account, but I think we can bypass that

looking at `BaseRule1$$SendMain` i notice that the mv parameter in the
query string is actually referred to as MasterVersion, in the disassembly,
we will hardcode it for now

the code that generates the time_difference field is confusing, not sure
why it creates a 2017-01-01 date, but from the logs it seems to be 3600
for me so I'm guessing it's the offset from utc or something. I'll just
hardcode it for now

I decided to first do a quick test in kotlin using the same
OkHttp library to be as close as possible to the game

I ran into a stupid issue that had me banging my head on my keyboard for
an entire day - the server bails out with a 500 error if your
`content-type` is `application/json; charset=utf-8` instead of just
`application/json` . OkHttp automatically adds the charset if you call
`toRequestBody`

this is the code I ended up with, way more elaborate than it needs to for
this simple test, but you have to keep in mind I was troubleshooting this
with different requests all day

for PublicEncrypt we want OAEP padding because the bool passed to
`RSACryptoServiceProvider$$Encrypt` is true (check the msdn docs)

since java and kotlin can't handle .net xml keys i converted it to PEM
using this tool
https://gist.github.com/Francesco149/8c6288a853dd010a638892be2a2c48af

OAEP padding is randomized so don't worry if the encrypted data looks
different for the same input

for md5 i pretty much copied the game's code 1:1 even though it's
unnecessary to go through BigInteger

for the resemara detection id I generated a random uuid instead of using
a real google advertising id and hashed it with the package name as the
game does. the server happily accepted it. a random md5 hash would
probably work too

I'm not sure yet what the mask field even does since it's random bytes,
maybe it's just there so the server can verify the signature

```kotlin
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.*
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import java.util.Base64
import java.util.UUID
import java.math.BigInteger
import kotlin.random.Random

const val ServerEndpoint = "https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1010"
const val StartupKey = "G5OdK4KdQO5UM2nL"
const val RSAPublicKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ZUSWq8LCuF2JclEp6uuW9+yddLQvb2420+F8
rxIF8+W53BiF8g9m6nCETdRw7RVnzNABevMndCCTD6oQ6a2w0QpoKeT26578UCWtGp74NGg2Q2fH
YFMAhTytVk48qO4ViCN3snFs0AURU06niM98MIcEUnj9vj6kOBlOGv4JWQIDAQAB
-----END PUBLIC KEY-----"""
const val PackageName = "com.klab.lovelive.allstars"
const val MasterVersion = "646e6e305660c69f"

fun md5(str: String): String {
  val digest = MessageDigest.getInstance("MD5")
  digest.reset()
  digest.update(str.toByteArray())
  val hash = digest.digest();
  return BigInteger(1, hash).toString(16).padStart(32, '0')
}

fun publicEncrypt(key: PublicKey, data: ByteArray): ByteArray {
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
  cipher.init(Cipher.ENCRYPT_MODE, key);
  return cipher.doFinal(data);
}

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

fun hmacSha1(key: ByteArray, data: ByteArray): String {
  val hmacKey = SecretKeySpec(key, "HmacSHA1")
  val hmac = Mac.getInstance("HmacSHA1")
  hmac.init(hmacKey)
  return hmac.doFinal(data).toHexString()
}

var requestId = 0;
var sessionKey = StartupKey;

fun call(path: String, payloadJson: String, mv: Boolean, t: Boolean,
  u: Int = 0)
{
  requestId = requestId + 1;
  var pathWithQuery = path + "?p=a";
  if (mv) {
    pathWithQuery += "&mv=$MasterVersion"
  }
  pathWithQuery += "&id=$requestId"
  if (u != 0) {
    pathWithQuery += "&u=$u"
  }
  if (t) {
    val millitime = System.currentTimeMillis()
    pathWithQuery += "&t=$millitime"
  }
  println(pathWithQuery);
  val hashData = pathWithQuery + " " + payloadJson
  val hash = hmacSha1(sessionKey.toByteArray(), hashData.toByteArray())
  val json = """[$payloadJson,"$hash"]"""
  println(json)
  val client = OkHttpClient()
  val request = Request.Builder()
    .url("$ServerEndpoint$pathWithQuery")
    .post(json.toByteArray()
      .toRequestBody("application/json".toMediaType()))
    .build()
  client.newCall(request).execute().use { response ->
    if (!response.isSuccessful) {
      println("unexpected code $response")
    }
    for ((name, value) in response.headers) {
      println("$name: $value")
    }
    println(response.body!!.string())
  }
}

fun main(args: Array<String>) {
  val kf = KeyFactory.getInstance("RSA");
  val keyBytes = Base64.getDecoder().decode(
    RSAPublicKey
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace("\\s+".toRegex(),"")
  )
  val keySpecX509 = X509EncodedKeySpec(keyBytes)
  val pubKey = kf.generatePublic(keySpecX509)
  val base64 = Base64.getEncoder()
  val advertisingId = UUID.randomUUID().toString()
  val resemara = md5(advertisingId + PackageName)
  val randomBytes = Random.nextBytes(32)
  val maskBytes = publicEncrypt(pubKey, randomBytes)
  val mask = base64.encodeToString(maskBytes)
  val payloadJson = """{"mask":"$mask","resemara_detection_identifier":"$resemara","time_difference":3600}"""
  call("/login/startup", payloadJson, true, true);
}
```

and here's the script I use on linux to build and run it:
https://gist.github.com/636d7efeff523b152a3039758d3ea9f6

note: you need kotlin 1.3.41 or higher to build and run with my script

if we run it, we get:

```
# checking dependencies
[ok] okhttp-4.2.2.jar
[ok] okio-2.2.2.jar

# compiling

# running
/login/startup?p=a&mv=646e6e305660c69f&id=1&t=CENSORED_TIME
[{"mask":"CENSORED","resemara_detection_identifier":"CENSORED","time_difference":3600},"CENSORED_HASH"]
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Server: nginx
Date: CENSORED
Vary: Accept-Encoding
X-Cache: Miss from cloudfront
Via: 1.1 CENSORED.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: CENSORED
X-Amz-Cf-Id: CENSORED
[CENSORED_TIME,"646e6e305660c69f",0,{"user_id":CENSORED,"authorization_key":"CENSORED"},"CENSORED_HASH"]
```

here's also a python version I wrote while I was troubleshooting
https://gist.github.com/e801c077ad2e3e9f82f2da8233735707

so there you have it! we made our first communication with the server
successfully. this is just the beginning though, we have all the more
convoluted session key xoring ahead of us as well as some seemingly
obfuscated fields like asset_state which is generated by
`_KJACore_AssetStateLogGenerateV2` in `libjackpot-core.so`

another interesting quirk I noticed is that the server also throws a 500
error if your query parameters in the url aren't in the same order as
the game, which can cause problems with libs that parse and sort query
params

just to be 100% accurate, I decided to use the exact same version of okhttp
by downgrading to 3.9.1 (you can find it in the java strings by searching
for 'okhttp/') which has a slightly different API

so let's take a look at what happens once the startup response is received
once again in `DMHttpApi.__c__DisplayClass14_2$$_Login_b__4`

```c
    userId = (Array *)StartupResponse$$get_UserId(startupResponse);
    xoredAuthorizationKey = httpApi->SessionKey;

    ...

    authorizationKey = (Array *)StartupResponse$$get_AuthorizationKey(startupResponse);
    authorizationKey = Convert$$FromBase64String(authorizationKey);
    xoredAuthorizationKey = Lib$$XorBytes(xoredAuthorizationKey,authorizationKey);
    UserKey$$SetIDPW(userId,xoredAuthorizationKey,0);
```

which in short is

* decode the base64 authorization_key
* xor the current authorization_key with the current session key (which
  starts as StartupKey)
* remember the xored auth key and user id for later

then in `DMHttpApi$$Login` it gets the user id and key back and just
passes them onto the next step of the state machine which I assume
is `DMHttpApi.__c__DisplayClass14_0$$_Login_b__0`. here it stores the
user id and session key in some class

```c
    puVar4 = (undefined4 *)(displayClass + 0xc);
    *puVar4 = user_id;
    *(undefined4 *)(displayClass + 0x14) = param_1;
    pBytes_ = (Array **)(displayClass + 0x10);
    *pBytes_ = session_key;
```

reveals us the UserID field of DMHttpApi

```c
  iUserId = 0;
  FUN_021f75fc(&iUserId,user_id,Method$Nullable_int_..ctor());

  ...

  pDVar1 = Class$DotUnder.DMHttpApi->Instance;
  pDVar1->UserId = iUserId;
```

updates the session key with the xored one and increases the auth count
which will be in the login request

```c
Class$DotUnder.DMHttpApi->Instance->SessionKey = *pBytes_;
authCount = UserKey$$IncrAuthCount(0);
```

if you actually look at `UserKey$$IncrAuthCount` you will see that it's
stored in local storage and likely persists across reboots

then it goes on to generate the mask as usual by signing 32 random bytes

```c
randomBytes_ = (Array *)DMCryptography$$RandomBytes(0x20)
...
*pBytes_ = randomBytes_;
...
mask = DMCryptography$$PublicEncrypt(randomBytes_);
...
mask = Convert$$ToBase64String(mask,0);
```

this is where we hit our next roadblock, the asset_state field. it's
generated from the same random bytes that are signed for mask

```c
  randomBytes_ = Convert$$ToBase64String(*pBytes_,0);
  assetStateLog = Platform$$GenerateAssetStateLog(randomBytes_,0);
  loginApi = Instantiate1(Class$DotUnder.SVAPI.Login);
  Login$$.ctor(loginApi,0);
...
  userId = *pUserId;
  loginRequest = Instantiate1(Class$DotUnder.Structure.LoginRequest);
  LoginRequest$$.ctor(loginRequest,userId,authCount,mask,assetStateLog,0);
```

if we look at `Platform$$GenerateAssetStateLog` it calls into
`AndroidPlatform$$GenerateAssetStateLog` which constructs a StringBuilder
of capacity 1024 bytes and calls into `libjackpot-core.so`

```c
void AndroidPlatform$$_KJACore_AssetStateLogGenerateV2
               (undefined4 stringBuilder,undefined4 capacity,String *base64RandomBytes)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char *local_38;
  undefined4 local_34;
  char *local_30;
  undefined local_1c;
  
  if (DAT_03706760 == (code *)0x0) {
    local_34 = 0xc;
    local_30 = "_KJACore_AssetStateLogGenerateV2";
    local_1c = 0;
    local_38 = "jackpot-core";
    DAT_03706760 = (code *)FUN_008a5040(&local_38);
    if (DAT_03706760 == (code *)0x0) {
      uVar1 = FUN_0089f2d0(
                          "Unable to find method for p/invoke: \'_KJACore_AssetStateLogGenerateV2\'"
                          );
      ThrowSomeOtherException(uVar1,0,0);
      caseD_15();
      return;
    }
  }
  uVar1 = FUN_008a54c0(stringBuilder);
  uVar2 = FUN_008a5318(base64RandomBytes);
  (*DAT_03706760)(uVar1,capacity,uVar2);
  FUN_008a576c(stringBuilder,uVar1);
  FUN_008a530c(uVar1);
  FUN_008a530c(uVar2);
  return;
}
```

so I disassemble libjackpot-core.so and see what this function is all about
and oh boy, it calls a giant obfuscated function that appears to be an
extremely obfuscated way to produce some kind of string. the output also
seems to be affected by the random base64 bytes. it does all kinds of
convoluted stuff with std::strings and at some point it even seems to
open files.

I could sit here for a month and maybe make sense of it, but
what I am actually going to do is hook it and grab a few valid outputs with
a few random strings of bytes and shuffle between those. I don't think
this asset_state field holds any meaningful info anyway since it's so
short. it's probably just checked against the random bytes

the hook

```c
static
String* (*original_GenerateAssetStateLog)(String* base64RandomBytes);

static
String* hooked_GenerateAssetStateLog(String* base64RandomBytes) {
  String* res;
  log("random bytes:");
  String_log(base64RandomBytes);
  res = original_GenerateAssetStateLog(base64RandomBytes);
  log("asset state:");
  String_log(res);
  return res;
}
```

result

```
10-21 16:04:40.515  7151  7176 D sniffas.c: random bytes:
10-21 16:04:40.515  7151  7176 D sniffas.c: +zuyNj+IFhSydzEMTHnrBCyUO0b3CvQt5nOWwxpNKcE=
10-21 16:04:40.776  7151  7176 D sniffas.c: asset state:
10-21 16:04:40.776  7151  7176 D sniffas.c: OqwKkOuhtlyuSzCj95pXUjtEo65SuYtUI3OlrxWWSjz7IEyicAMR7/IWuc822gc2cQXHjHY2ASHjQFfdONJNOU5gMM5w4g3Dj2K+iv1HDPZTAdtd8BURk7Iu+HVqxACI2g==
```

let's hardcode these values temporarily

ok so while implementing this I noticed that it's not the session key that
is xored with the auth key, seems like it's actually the random bytes.
i thought it was weird that the string sizes didn't match

in `DMHttpApi$$Login`

```c
    randomBytes = DMCryptography$$RandomBytes(0x20);
    *(undefined4 *)(displayClass14_2 + 8) = randomBytes;

...

    actionStartupRequest = thunk_FUN_008ae738(Class$Action_StartupRequest_);
    FUN_024470b8(actionStartupRequest,displayClass14_2,
                 Method$DMHttpApi.__c__DisplayClass14_2._Login_b__3(),
                 Method$Action_StartupRequest_..ctor());
```

see how the first param to Login_b__3 is the displayclass that contains
the random bytes at offset 8?

Login_b__3 just passes it through and then Login_b__4 uses it:

```c
    userId = (Array *)StartupResponse$$get_UserId(startupResponse);
    xoredAuthorizationKey = *(Array **)((int)displayClass + 8);
  }
  authorizationKey = (Array *)StartupResponse$$get_AuthorizationKey(startupResponse);
  if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
     (*(int *)(Class$System.Convert + 0x70) == 0)) {
    FUN_0087fd40();
  }
  authorizationKey = Convert$$FromBase64String(authorizationKey);
  xoredAuthorizationKey = Lib$$XorBytes(xoredAuthorizationKey,authorizationKey);
```

here's the updated code, I also cleaned it up a little bit

```kotlin
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody

const val ServerEndpoint =
  "https://jp-real-prod-v4tadlicuqeeumke.api.game25.klabgames.net/ep1010"
const val StartupKey = "G5OdK4KdQO5UM2nL"
const val RSAPublicKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ZUSWq8LCuF2JclEp6uuW9+yddLQvb2420+F8
rxIF8+W53BiF8g9m6nCETdRw7RVnzNABevMndCCTD6oQ6a2w0QpoKeT26578UCWtGp74NGg2Q2fH
YFMAhTytVk48qO4ViCN3snFs0AURU06niM98MIcEUnj9vj6kOBlOGv4JWQIDAQAB
-----END PUBLIC KEY-----"""
const val PackageName = "com.klab.lovelive.allstars"
const val MasterVersion = "646e6e305660c69f"

val kf = KeyFactory.getInstance("RSA")
val keyBytes = Base64.getDecoder().decode(
  RSAPublicKey
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace("\\s+".toRegex(), "")
)
val keySpecX509 = X509EncodedKeySpec(keyBytes)
val pubKey = kf.generatePublic(keySpecX509)

val gson = Gson()
val base64Encoder = Base64.getEncoder()
val base64Decoder = Base64.getDecoder()

fun md5(str: String): String {
  val digest = MessageDigest.getInstance("MD5")
  digest.reset()
  digest.update(str.toByteArray())
  val hash = digest.digest()
  return BigInteger(1, hash).toString(16).padStart(32, '0')
}

fun publicEncrypt(data: ByteArray): ByteArray {
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")
  cipher.init(Cipher.ENCRYPT_MODE, pubKey)
  return cipher.doFinal(data)
}

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
fun ByteArray.xor(other: ByteArray) =
  (zip(other) { a, b -> (a.toInt() xor b.toInt()).toByte() }).toByteArray()

fun hmacSha1(key: ByteArray, data: ByteArray): String {
  val hmacKey = SecretKeySpec(key, "HmacSHA1")
  val hmac = Mac.getInstance("HmacSHA1")
  hmac.init(hmacKey)
  return hmac.doFinal(data).toHexString()
}

var requestId = 0
var sessionKey = StartupKey.toByteArray()

const val WithMasterVersion = 1 shl 1
const val WithTime = 1 shl 2
const val PrintHeaders = 1 shl 3

fun call(
  path: String,
  payload: String,
  flags: Int = 0,
  userId: Int = 0
): String {
  requestId += 1
  var pathWithQuery = path + "?p=a"
  if ((flags and WithMasterVersion) != 0) {
    pathWithQuery += "&mv=$MasterVersion"
  }
  pathWithQuery += "&id=$requestId"
  if (userId != 0) {
    pathWithQuery += "&u=$userId"
  }
  if ((flags and WithTime) != 0) {
    val millitime = System.currentTimeMillis()
    pathWithQuery += "&t=$millitime"
  }
  println("-> POST $pathWithQuery")
  val hashData = pathWithQuery + " " + payload
  val hash = hmacSha1(sessionKey, hashData.toByteArray())
  val json = """[$payload,"$hash"]"""
  println("-> $json")
  val JSON = MediaType.parse("application/json")
  val client = OkHttpClient()
  val request = Request.Builder()
    .url("$ServerEndpoint$pathWithQuery")
    .post(RequestBody.create(JSON, json.toByteArray()))
    .build()
  val response = client.newCall(request).execute()
  if (!response.isSuccessful) {
    println("unexpected code $response")
  }
  if ((flags and PrintHeaders) != 0) {
    val headers = response.headers()
    for (i in 0..headers.size() - 1) {
      val name = headers.name(i)
      val value = headers.value(i)
      println("<- $name: $value")
    }
  }
  val s = response.body()!!.string()
  println("<- $s")
  return s
}

data class StartupRequest(
  val mask: String,
  val resemara_detection_identifier: String,
  val time_difference: Int
)

data class StartupResponse(
  val user_id: Int,
  val authorization_key: String
)

fun startup(randomBytes: ByteArray): StartupResponse? {
  val advertisingId = UUID.randomUUID().toString()
  val resemara = md5(advertisingId + PackageName)
  val maskBytes = publicEncrypt(randomBytes)
  val mask = base64Encoder.encodeToString(maskBytes)
  val result = call(
    path = "/login/startup",
    payload = gson.toJson(StartupRequest(
      mask = mask,
      resemara_detection_identifier = resemara,
      time_difference = 3600
    ), StartupRequest::class.java),
    flags = WithMasterVersion or WithTime
  )
  val array = JsonParser.parseString(result).getAsJsonArray()
  for (x in array) {
    if (x.isJsonObject()) {
      return gson.fromJson(x, StartupResponse::class.java)
    }
  }
  return null
}

data class LoginRequest(
  val user_id: Int,
  val auth_count: Int,
  val mask: String,
  val asset_state: String
)

var authCount = 0

fun login(userId: Int) {
  authCount += 1
  val randomBytesBase64 = "+zuyNj+IFhSydzEMTHnrBCyUO0b3CvQt5nOWwxpNKcE="
  val randomBytes = base64Decoder.decode(randomBytesBase64)
  val maskBytes = publicEncrypt(randomBytes)
  val mask = base64Encoder.encodeToString(maskBytes)
  val result = call(
    path = "/login/login",
    payload = gson.toJson(LoginRequest(
      user_id = userId,
      auth_count = authCount,
      mask = mask,
      asset_state = "OqwKkOuhtlyuSzCj95pXUjtEo65SuYtUI3OlrxWWSjz7IEyicA" +
        "MR7/IWuc822gc2cQXHjHY2ASHjQFfdONJNOU5gMM5w4g3Dj2K+iv1HDPZTAdtd" +
        "8BURk7Iu+HVqxACI2g=="
    ), LoginRequest::class.java),
    userId = userId
  )
  val prettyPrint = GsonBuilder().setPrettyPrinting().create()
  val array = JsonParser.parseString(result).getAsJsonArray()
  println(prettyPrint.toJson(array))
}

fun main(args: Array<String>) {
  val randomBytes = Random.nextBytes(32)
  val startupResponse = startup(randomBytes)
  println(startupResponse!!)
  val authKey = base64Decoder.decode(startupResponse.authorization_key)
  println(authKey.toHexString())
  println(randomBytes.toHexString())
  sessionKey = authKey.xor(randomBytes)
  println(sessionKey.toHexString())
  login(startupResponse.user_id)
}
```

and sure enough, we are logged in!

I will most likely generate a large database of "random" bytes and their
correct asset_state 

![we are logged in](pic2.png)

I took a closer look at the crazy asset_state generator function. compiler
optimizations mangle the decompilation a lot but with patience you can
repair it. it took around 2 days to name everything and recognize which
were std::string operations, mostly by guessing

the first part is reading from a huge string and copying to local arrays,
which generates a lot of pointless vars, i redefined the whole memory area
to be a large array. it's also appending some stuff in between

this huge string is:

```
846t07:9t1:80+4/t\b2<5\x1c>5>):/4)[4+>5[sr\x17846t07:9t1:80+4/t\b2<5\x1c>5>):/4)`[:-:27:97>[sr\x01[<>/[s\x12r\x171:-:t7:5<t\b/)25<`[874(>[sr\r[846t07:9t1:80+4/t\x1a((>/(\x1f2<>(/\x1c>5>):/4)[s\x171:-:t7:5<t\b/)25<`r\x17846t07:9t1:80+4/t\x1a((>/(\x1f2<>(/\x1c>5>):/4)`[ +,m\x06#6#m\x0f#,#%\'&m\x0311\'/.;o\x01\x11*#02l&..BN\\BL\\GN]_KCCKFHJ\\[XN\\A@[NYNFCNMCJ/\\FHAN[Z]JKFHJ\\[XN\\A@[NYNFCNMCJ/.+ +.p!22l1-B
```

also it's not all ascii, so I'm not 100% sure it's really a single string

first thing it does is save the first 3 chars of the base64 randombytes

c
```c
  second_char = base64RandomBytes[1];
  stack_guard = __stack_chk_guard;
  third_char = base64RandomBytes[2];
  first_char = *base64RandomBytes;
```

then it constructs `tmp2` by copying 32 characters at huge_string + 0x102
followed by `J/`

```c
  huge_string_int32 = (int *)(huge_string + 0x102);
  it1 = (int *)tmp2;
  do {
    ptr_2 = huge_string_int32 + 2;
    int1 = huge_string_int32[1];
    *it1 = *huge_string_int32;
    it1[1] = int1;
    it1 = it1 + 2;
    huge_string_int32 = ptr_2;
  } while (ptr_2 != (int *)(huge_string + 0x122));
                    /* appends "J/" */
  *(undefined2 *)it1 = 0x2f4a;
```

then it constructs `tmp1` by copying 24 characters from huge_string + 0x124
followed by "FCNM" followed by 3 more chars copied past the end of the loop
for a total of 30 characters

```c
  buf2 = (undefined4 *)tmp1;
  huge_string_int32_ = (undefined4 *) (huge_string + 0x124);
  do {
    ptr_ = huge_string_int32_;
    buf2_ = buf2;
    int1_ = ptr_[1];
    *buf2_ = *ptr_;
    buf2_[1] = int1_;
    buf2 = buf2_ + 2;
    huge_string_int32_ = ptr_ + 2;
  } while (ptr_ + 2 != (undefined4 *) (huge_string + 0x13c));
  uVar2 = *(undefined2 *)(ptr_ + 3);
  cVar1 = *(char *)((int)ptr_ + 0xe);
                    /* appends "FCNM" */
  buf2_[2] = 0x4d4e4346;
                    /* copies 3 extra chars past the above loop after "FCNM" */
  *(undefined2 *)(buf2_ + 3) = uVar2;
  *(char *)((int)buf2_ + 0xe) = cVar1;
```

then it constructs `tmp3` by copying 8 characters from huge_string + 0x143
followed by "2l1-" followed by 1 more char copied past the end of the loop
for a total of 14 characters

```c
  buf2 = tmp3;
  huge_string_int32_ = (undefined4 *) (huge_string + 0x143);
  do {
    ptr_ = huge_string_int32_;
    buf2_ = buf2;
    int1_ = ptr_[1];
    *buf2_ = *ptr_;
    buf2_[1] = int1_;
    buf2 = buf2_ + 2;
    huge_string_int32_ = ptr_ + 2;
  } while (ptr_ + 2 != (undefined4 *) (huge_string + 0x14b));
  cVar1 = *(char *)(ptr_ + 3);
                    /* appends "2l1-" */
  buf2_[2] = 0x2d316c32;
                    /* copies 1 extra char past the above loop after "211-" */
  *(char *)(buf2_ + 3) = cVar1;
```

then it calls a function that i named `xor_until_match` on the three bufs

```c
  xor_until_match('/',tmp2);
  xor_until_match('/',tmp1);
  xor_until_match('B',tmp3);
```

which xors every character with the given character until it finds a
matching character which xors to zero:

```c
char * xor_until_match(char c,char *str)

{
  char *p;
  char tmp;
  
  p = str;
  do {
    tmp = *p;
    *p = tmp ^ c;
    p = p + 1;
  } while ((byte)(tmp ^ c) != 0);
  return str;
}
```

this also zero-terminates the strings, once the matching character is found

then it proceeds to initialize two std strings. how did I know they were
std strings? it took a lot of guess work and looking at the functions
that are later called on them

```c
  string((int)&stdstring1);
  string((int)&stdstring2);
```

I manually mapped a few fields like start and end for std::string, again
by guessing

then it calls dladdr on a fixed address which is this very function. this
is used to get the path to `libjackpot-core.so`

I mapped the Dl_info struct from [the manpages](http://man7.org/linux/man-pages/man3/dladdr.3.html)

```c
  int1 = dladdr(0x244b9,&dli);
  if (int1 != 0) {
    string_from_c((int)&path_to_libjackpot,dli.dli_fname);
```

this overly complicated thing (probably mangled by optimization) seems
to strip the filename from the path (last element)

```c
    start = path_to_libjackpot.start;
    len = path_to_libjackpot.end + -(int)path_to_libjackpot.start;
    if (len == (char *)0x0) {
LAB_000245b4:
      it2 = (char *)0xffffffff;
    }
    else {
                    /* i think this whole thing just strips the filename from the full path */
      int1 = (int)len >> 2;
      end = path_to_libjackpot.end;
      while (it2 = end, 0 < int1) {
        if (end[-1] == '/') goto LAB_00024628;
        if (end[-2] == '/') {
          it2 = end + -1;
          goto LAB_00024628;
        }
        if (end[-3] == '/') {
          it2 = end + -2;
          goto LAB_00024628;
        }
        if (end[-4] == '/') {
          it2 = end + -3;
          goto LAB_00024628;
        }
        int1 = int1 + -1;
        end = end + -4;
      }
      pcVar8 = end + -(int)path_to_libjackpot.start;
      if (pcVar8 == (char *)0x2) {
LAB_00024610:
        it2 = end;
        if (end[-1] != '/') {
          end = end + -1;
LAB_0002461a:
          it2 = end;
          if (end[-1] != '/') {
            it2 = path_to_libjackpot.start;
          }
        }
      }
      else {
        if (pcVar8 == (char *)0x3) {
          if (end[-1] != '/') {
            end = end + -1;
            goto LAB_00024610;
          }
        }
        else {
          it2 = path_to_libjackpot.start;
          if (pcVar8 == (char *)0x1) goto LAB_0002461a;
        }
      }
LAB_00024628:
      if (it2 == path_to_libjackpot.start) goto LAB_000245b4;
      it2 = it2 + (-1 - (int)path_to_libjackpot.start);
    }
```

it then stores second and third char of the random bytes base64 modulo 3

```c
                    /* the decompiler doesn't show it, but the remainder is stored in
                       second_char_mod3 and third_char_mod3 */
    __aeabi_idivmod((uint)second_char,3);
    __aeabi_idivmod((uint)third_char,3);
```

here it appends tmp3 to the base directory of libjackpot-core.so

```c
    if (len < it2) {
      it2 = len;
    }
    libjackpot_directory.end = (char *)&libjackpot_directory;
    libjackpot_directory.start = (char *)&libjackpot_directory;
    string_from_range(&libjackpot_directory,start,start + (int)it2);
    string_concatenate_char(&tmpstring,&libjackpot_directory,&"/");
    string_from_c((int)&tmp3_string,tmp3);
    string_concatenate(&tmp3_path,&tmpstring,&tmp3_string);
    operator_delete_(&tmp3_string);
    operator_delete_(&tmpstring);
    operator_delete_(&libjackpot_directory);
```

i think this is a good point to take a break and either hook or implement
this first part of the function to see what the tmp strings are

after looking around for a bit, I think we can hook the very next function
that's called. it reads the given file computes one of three hashes: md5,
sha-1 or sha-256 depending on the parameter passed in, which in this case
in `base64randombytes[1] & 3`

```c
    if ((first_char & 1) == 0) {
      conditional_hash(&libjackpot_hash,&path_to_libjackpot,second_char_mod_3);
      conditional_hash(&tmp3_hash,&tmp3_path,second_char_mod_3);
```

here's what the hashing function looks like

```c
char ** conditional_hash(char **pphash,std__string *path,int type)

{
  if (type == 0) {
    md5(pphash,path);
  }
  else {
    if (type == 1) {
      sha1(pphash,(char *)path);
    }
    else {
      if (type == 2) {
        sha256(pphash,path);
      }
      else {
        *pphash = (char *)0x0;
        pphash[1] = (char *)0x0;
      }
    }
  }
  return pphash;
}
```

the way I figured out which hashes it was doing was by looking at the
functions. they call some initialization function:

```c
void ** md5(void **pphash,std__string *param_2)

{
  FILE *__stream;
  size_t sVar1;
  undefined auStack1168 [4];
  undefined auStack1164 [16];
  undefined auStack1148 [88];
  undefined auStack1060 [1024];
  int local_24;
  
  local_24 = __stack_chk_guard;
  __stream = fopen(param_2->start,"rb");
  if (__stream == (FILE *)0x0) {
    *pphash = (void *)0x0;
    pphash[1] = (void *)0x0;
  }
  else {
    md5_hash_initial(auStack1168,auStack1148);
    while (sVar1 = fread(auStack1060,1,0x400,__stream), sVar1 != 0) {
      md5_hash_update(auStack1168,auStack1148,auStack1060,sVar1);
    }
    fclose(__stream);
    md5_finalize(auStack1168,auStack1164,auStack1148);
    clone_memory(pphash,auStack1164,0x10);
  }
  if (local_24 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return pphash;
}
```

that initialization function has some very well known constants that I
googled

```c
void md5_hash_initial(undefined4 param_1,undefined4 *param_2)

{
  param_2[5] = 0;
  param_2[4] = 0;
  *param_2 = 0x67452301;
  param_2[1] = 0xefcdab89;
  param_2[2] = 0x98badcfe;
  param_2[3] = 0x10325476;
  return;
}
```

initially I thought they were all modified versions of sha1 with slightly
different initial parameters but then I realized that md5, sha1, sha256 all
have common hashes and from the output size you can tell which one it is
(16, 24, 32 bytes)

also, that memory_clone function reveals that pphash is a struct that
contains data ptr and length

so let's hook this conditional_hash function and see what the other file is

we have a bit of a problem, this function appears to be using thumb
instructions. we need different instructions to hook it

```
000233dc 10 b5           push       { r4, lr }
000233de 04 46           mov        r4,pphash
000233e0 12 b9           cbnz       type,LAB_000233e8
000233e2 ff f7 19 ff     bl         md5
```

long story short the an absolute jump is performed with

```
ldr.w   pc, [pc]
.word 0xbaadf00d
```

which assembles to

```
f8 df f0 00
0d f0 ad ba
```

baadf00d would be the target address

another issue is that the function uses a relative jump right at the
beginning, so instead of calling the original through a trampoline,
we will instead replace the entire function with our own and to that
simple if/else ourselves

we also have to compile the hook with thumb instructions by using
`__attribute__((target("thumb")))`

here's the hook I ended up with:

```c
typedef struct {
  char unk[16];
  char* end;
  char* start;
} std_string;

typedef struct {
  char* data;
  int length;
} hash_array;

/* unused */
static hash_array* (*original_hash)(hash_array* pphash, std_string* path,
  int type);

hash_array* (*md5)(hash_array* hash, std_string* path);
hash_array* (*sha1)(hash_array* hash, std_string* path);
hash_array* (*sha256)(hash_array* hash, std_string* path);

static
__attribute__((target("thumb")))
hash_array* hooked_hash(hash_array* hash, std_string* path, int type) {
  hash_array* res;
  char buf[1024];
  char* p = buf;
  int i;
  p += sprintf(p, "hash called with type %d on ", type);
  memcpy(p, path->start, path->end - path->start);
  p[path->end - path->start] = 0;
  log(buf);
  switch (type) {
    case 0: res = md5(hash, path); break;
    case 1: res = sha1(hash, path); break;
    case 2: res = sha256(hash, path); break;
    default:
      log("unknown hash!");
      hash->data = 0;
      hash->length = 0;
      return hash;
  }
  p = buf;
  p += sprintf(p, "result: ");
  for (i = 0; i < res->length; ++i) {
    p += sprintf(p, "%02x", hash->data[i]);
  }
  log(buf);
  return res;
}
```

here's where I assign the function pointers for the 3 hashes, I have to
set the lowest bit to 1 to ensure that the cpu knows it should stay in
thumb mode

```c
  /* | 1 forces thumb mode */
#define f(name, addr) \
  *(int*)&name = ((int)dli.dli_fbase + addr) | 1

  f(md5, 0x13218);
  f(sha1, 0x132ac);
  f(sha256, 0x13344);

#undef f
```

and here's the output:

```
hash called with type 1 on /data/app/com.klab.lovelive.allstars-UVN-H8XkmXR-vs5WM0Fzvw==/lib/arm/libjackpot-core.so
result: 5a3cb86aa9b082d6a1c1dfa6f73dd431d7f14e18
hash called with type 1 on /data/app/com.klab.lovelive.allstars-UVN-H8XkmXR-vs5WM0Fzvw==/lib/arm/libil2cpp.so
result: c4387c429c50c4782ab3df409db3abcfa8fadf79
```

alright, so the other file it's hashing is il2cpp

next, it xors the two hashes together, formats the result to a hexstring
and puts it into stdstring1

```c
      array_xor(&xored_hashes,&libjackpot_hash,&tmp3_hash);
      std_hexstring_from_array(&tmp3_string,&xored_hashes);
      string_assignment((int)&stdstring1,(int)&tmp3_string);
```

the xor function was obvious

```c
some_kind_of_array * array_xor(some_kind_of_array *dst,some_kind_of_array *a,some_kind_of_array *b)

{
  char *result;
  int len2;
  uint i;
  int len1;
  
  len2 = b->length;
  len1 = a->length;
  dst->data = (char *)0x0;
  dst->length = 0;
  if (len1 == len2) {
    if (len1 != 0) {
      result = (char *)operator.new(len1);
      dst->data = result;
      dst->length = len1;
    }
    i = 0;
    while (i < (uint)a->length) {
      dst->data[i] = a->data[i] ^ b->data[i];
      i = i + 1;
    }
  }
  return dst;
}
```

`std_hexstring_from_array` was tricky to figure out. I hooked
string_from_range which is called inside of it:

```c
void (*basic_string)(void* s, int len);
void (*original_string_from_range)(std_string* s, char* start, char* end);

static
__attribute__((target("thumb")))
void hooked_string_from_range(std_string* s, char* start, char* end) {
  char buf[1024];
  log("string from range");
  memcpy(buf, start, end - start);
  buf[end - start] = 0;
  log(buf);
  basic_string(s, end - start + 1);
  memcpy(s->start, start, end - start);
  s->end = s->start + (end - start);
  s->start[end - start] = 0;
}
```

and here's the result

```
string from range
/data/app/com.klab.lovelive.allstars-UVN-H8XkmXR-vs5WM0Fzvw==/lib/arm
hash called with type 2 on /data/app/com.klab.lovelive.allstars-UVN-H8XkmXR-vs5WM0Fzvw==/lib/arm/libjackpot-core.so
result: 66370b8c96de7266b02bfe17e696d8a61b587656a34b19fbb0b2768a5305dd1d
hash called with type 2 on /data/app/com.klab.lovelive.allstars-UVN-H8XkmXR-vs5WM0Fzvw==/lib/arm/libil2cpp.so
result: d30568d1057fecb31a16f4062239c1ec65b9c2beab41b836658b637dcb5a51e4
string from range
b532635d93a19ed5aa3d0a11c4af194a7ee1b4e8080aa1cdd53915f7985f8cf9
```

next, it calls another huge function that unencrypts more strings from
the huge_string we saw earlier.

```
      operator_delete_(&tmp3_string);
      operator_delete(&xored_hashes);
      operator_delete(&tmp3_hash);
      operator_delete(&libjackpot_hash);
      crazy_function(&tmp3_string,third_char_mod_3);
      string_assignment((int)&stdstring2,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
```

if we scroll down we can see a string_from_range call, let's see what our
earlier hook logs:

```
string from range
1be2103a6929b38798a29d89044892f3b3934184
```

if we google for this hash, we find the apkpure page for SIFAS. it must
be the package signature. using [this tool](https://github.com/warren-bank/print-apk-signature)
on the apk confirms it:

```
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Number of signers: 1
Signer #1 certificate DN: CN=AS Team, OU=Unknown, O=KLab Inc., L=Unknown, ST=Unknown, C=JP
Signer #1 certificate SHA-256 digest: 1d32dbcf91697d46594ad689d49bb137f65d4bb8f56a26724ae7008648131b82
Signer #1 certificate SHA-1 digest: 1be2103a6929b38798a29d89044892f3b3934184
Signer #1 certificate MD5 digest: 3f45f90cbcc718e4b63462baeae90c86
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 5b125027893d4e43b5a4c1a4359968b86f0c0be30f9ef012349ba41855f0ff67
Signer #1 public key SHA-1 digest: 447c28474fc0cba922d504b2fe88da0af35f2f0b
Signer #1 public key MD5 digest: 43935540d5670e2869d777751c96c9a4
```

there's a peculiar function call at the beginning of the function. it seems
to call a function from some class vtable. it's passing &tmp3_string and
thid_char_mod_3 as param

```c
int * call_some_class(undefined4 param_1,int *param_2)

{
  int *local_c [3];
  
  local_c[0] = some_class;
  if (some_class != (int *)0x0) {
    local_c[0] = param_2;
    (**(code **)(*some_class + 0x10))(some_class,local_c,0,*(code **)(*some_class + 0x10),param_1);
  }
  return local_c[0];
}
```

if we look at what else references some_class, we find that it's the jni
env, assigned on JNI_OnLoad. the parameter is well documented. it also
seems to be doing some interesting rng initialization

```c
undefined4 JNI_OnLoad(void *vm,void *reserved)

{
  initialize_rand_seed(vm);
  return 0x10006;
}

void initialize_rand_seed(void *vm)

{
  time_t __seedval;
  long rand;
  undefined4 first_rand;
  int extraout_r1;
  int extraout_r1_00;
  
  set_jni_env(vm);
  if (rng_initialized == 0) {
    __seedval = time((time_t *)(uint)rng_initialized);
    srand48(__seedval);
                    /* extract random numbers between 100 and 1000 until one matches the first
                       number extracted */
    rand = lrand48();
    __aeabi_idivmod(rand,900);
    do {
      rand = lrand48();
      __aeabi_idivmod(rand,900);
    } while (extraout_r1 + 100 == extraout_r1_00 + 100);
    matching_rand_xor_& = xor('&',extraout_r1 + 100);
    first_rand_xor_& = xor('&',extraout_r1_00 + 100);
    first_rand = xor('&',first_rand_xor_&);
    first_rand_xor_M = xor('M',first_rand);
    char_r = xor('r',0);
    rng_initialized = 1;
  }
  return;
}

void set_jni_env(undefined4 jni_env)

{
  jni_env = jni_env;
  return;
}
```

the jni call is being passed `third_char_mod_3` so I have a feeling that
decides which hash to use like with the other hashing function

```c
jniresult = call_jni_env(str,(int *)(int)third_char_mod_3);
```

if we scroll down further we can find more calls into the jni env

```c
  uVar4 = FUN_00023124(jniresult,tmpint__,tmp4,tmp5);
  uVar5 = FUN_00023124(jniresult,tmpint__,tmp6,tmp7);
  uVar6 = FUN_00023124(jniresult,tmpint__,tmp8,tmp9);
```

right before this, we have a bunch of xor_until_match calls. let's hook
those and log all the unencrypted strings

for some reason i had to hook 1 instruction into the func otherwise it
would crash, either way here's the results

```
xor until match '['
com/klab/jackpot/SignGenerator
xor until match '['
open
xor until match '['
()Lcom/klab/jackpot/SignGenerator;
xor until match '['
available
xor until match '['
()Z
xor until match '['
get
xor until match '['
(I)Ljava/lang/String;
xor until match '['
close
xor until match '['
()V
string from range
3f45f90cbcc718e4b63462baeae90c86
```

so yeah, time to pull up the java side of the code

nothing special going on in the constructor, just grabbing the sig bytes

```java
void SignGenerator(SignGenerator this)

{
  PackageManager ref;
  String pSVar1;
  PackageInfo pPVar2;
  byte[] pbVar3;
  CertificateFactory ref_00;
  Certificate ref_01;
  Activity ref_02;
  Signature[] ppSVar4;
  Signature ref_03;
  InputStream ref_04;
  
  this.<init>();
  ref_02 = UnityPlayer.currentActivity;
  ref = ref_02.getPackageManager();
  pSVar1 = ref_02.getPackageName();
                    /* GET_SIGNATURES */
  pPVar2 = ref.getPackageInfo(pSVar1,0x40);
  ppSVar4 = pPVar2.signatures;
  if ((ppSVar4 == null) || (ppSVar4.length < 1)) {
    ref_03 = null;
  }
  else {
    ref_03 = ppSVar4[0];
  }
  if (ref_03 == null) {
    return;
  }
  pbVar3 = ref_03.toByteArray();
  if (pbVar3 == null) {
    return;
  }
  ref_04 = new InputStream(pbVar3);
  ref_00 = CertificateFactory.getInstance("X509");
  if (ref_00 == null) {
    return;
  }
  ref_01 = ref_00.generateCertificate(ref_04);
  checkCast(ref_01,X509Certificate);
  if (ref_01 == null) {
    return;
  }
  pbVar3 = ref_01.getEncoded();
  this.mBytes = pbVar3;
  return;
}
```

let's look at other methods of this class

```java
String get(SignGenerator this,int p1)

{
  boolean bVar1;
  MessageDigest ref;
  byte[] pbVar2;
  String ref_00;
  Object[] ppOVar3;
  BigInteger ref_01;
  StringBuilder ref_02;
  
  bVar1 = this.available();
  if (bVar1 == false) {
    return null;
  }
  if (p1 == 0) {
    ref = MessageDigest.getInstance("md5");
  }
  else {
    if (p1 == 1) {
      ref = MessageDigest.getInstance("sha1");
    }
    else {
      ref = MessageDigest.getInstance("sha256");
    }
  }
  if (ref == null) {
    return null;
  }
  pbVar2 = ref.digest(this.mBytes);
  ref_01 = new BigInteger(1,pbVar2);
  ref_02 = new StringBuilder();
  ref_02.append("%0");
  ref_02.append(pbVar2.length << 1);
  ref_02.append("X");
  ref_00 = ref_02.toString();
  ppOVar3 = new Object[1];
  ppOVar3[0] = ref_01;
  ref_00 = String.format(ref_00,ppOVar3);
  ref_00 = ref_00.toLowerCase();
  return ref_00;
}
```

exactly as predicted. p1 would be the `third_char_mod_3`

we can confidently rename the `crazy_function` to `get_package_signature`

there's one more trick to this madness, it swaps third/second char mod3
based on whether the first character of base64 bytes is even or odd

```c
    if ((first_char & 1) == 0) {
      conditional_hash(&libjackpot_hash,&path_to_libjackpot,second_char_mod_3);
                    /* il2cpp */
      conditional_hash(&tmp3_hash,&tmp3_path,second_char_mod_3);
      ptmp3_hash = &tmp3_hash;
      array_xor(&xored_hashes,&libjackpot_hash,&tmp3_hash);
      std_hexstring_from_array(&tmp3_string,&xored_hashes);
      string_assignment((int)&stdstring1,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
      operator_delete(&xored_hashes);
      operator_delete(&tmp3_hash);
      operator_delete(&libjackpot_hash);
      get_package_signature(&tmp3_string,third_char_mod_3,ptmp3_hash);
      string_assignment((int)&stdstring2,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
    }
    else {
      get_package_signature(&tmp3_string,(char)second_char_mod_3);
      string_assignment((int)&stdstring1,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
      conditional_hash(&libjackpot_hash,&path_to_libjackpot,third_char_mod_3);
      conditional_hash(&tmp3_hash,&tmp3_path,third_char_mod_3);
      array_xor(&xored_hashes,&libjackpot_hash,&tmp3_hash);
      std_hexstring_from_array(&tmp3_string,&xored_hashes);
      string_assignment((int)&stdstring2,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
      operator_delete(&xored_hashes);
      operator_delete(&tmp3_hash);
      operator_delete(&libjackpot_hash);
    }
```

note also how signature and xored hash are swapped between stdstring1/2

finally it concatenates the xored hashes and the package signature in
a single string, separating them with '-'.

```c
  if ((first_char & 1) == 0) {
    if (stdstring1.start == stdstring1.end) {
      string_from_c((int)&tmp3_string,tmp2);
      string_assignment((int)&stdstring1,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
    }
    if (stdstring2.start != stdstring2.end) goto LAB_0002480e;
    puVar3 = &stack0x00000104;
  }
  else {
    if (stdstring1.start == stdstring1.end) {
      string_from_c((int)&tmp3_string,tmp1);
      string_assignment((int)&stdstring1,(int)&tmp3_string);
      operator_delete_(&tmp3_string);
    }
    if (stdstring2.start != stdstring2.end) goto LAB_0002480e;
    puVar3 = &stack0x00000124;
  }
  string_from_c((int)&tmp3_string,puVar3 + -0x174);
  string_assignment((int)&stdstring2,(int)&tmp3_string);
  operator_delete_(&tmp3_string);
LAB_0002480e:
  string_concatenate_char(&tmp3_string,&stdstring1,"-");
  string_concatenate(&tmpstring,&tmp3_string,&stdstring2);
  operator_delete_(&tmp3_string);
```

the tmp1/tmp2 cases will never be reached as stdstring1 will always be set
to either the package signature or the xored hashes. therefore the only
code that matters is the part at `LAB_0002480e:` , where it concatenates
stdstring1 (either sig or xored hashes), "-", and stdstring2 (either sig
or xored hashes) into tmpstring

finally, we have a pretty convoluted xor encryption of some sort which
is stored into what was `xored_hashes` earlier and the result is
base64 encoded, and there's our `asset_state` field! we finally reached
the end of this crazy function

```c
  rounds = 10;
  xorkey = ((uint)(byte)*base64RandomBytes |
            (uint)(byte)base64RandomBytes[2] << 0x10 | (uint)(byte)base64RandomBytes[1] << 8 |
           (uint)(byte)base64RandomBytes[3] << 0x18) ^ 0x12d8af36;
  a = 0;
  b = 0;
  c = 0x2bd57287;
  d = 0;
  e = 0x202c9ea2;
  f = 0;
  g = 0x139da385;
  do {
    h = g;
    i = f;
    j = e;
    k = d;
    g = c;
    f = b;
    a = (a << 0xb | xorkey >> 0x15) ^ a;
    xorkey = xorkey << 0xb ^ xorkey;
    c = (g >> 0x13 | k << 0xd) ^ xorkey ^ g ^ (xorkey >> 8 | a << 0x18);
    d = k >> 0x13 ^ a ^ k ^ a >> 8;
    rounds = rounds + -1;
    xorkey = j;
    a = i;
    b = k;
    e = h;
  } while (rounds != 0);
  new_array(&xored_hashes,(int)(tmpstring.end + -(int)tmpstring.start));
  while (a = g, xorkey = f, rounds < (int)(tmpstring.end + -(int)tmpstring.start)) {
    b = (i << 0xb | j >> 0x15) ^ i;
    j = j << 0xb ^ j;
    e = (c >> 0x13 | d << 0xd) ^ j ^ c ^ (j >> 8 | b << 0x18);
    xored_hashes.data[rounds] = tmpstring.start[rounds] ^ (byte)e;
    rounds = rounds + 1;
    f = k;
    g = c;
    k = d;
    j = h;
    i = xorkey;
    c = e;
    d = d >> 0x13 ^ b ^ d ^ b >> 8;
    h = a;
  }
  base64_encode(base64_result,&xored_hashes);
```

so let's implement this abomination and see if it matches the game

this took a lot of work to get the operator precedence right and not have
signed-ness interfere in kotlin. i also hooked string_concat to check that
at least I had the hashes right

here is the result, and it produces asset_state values exactly like the
game

```kotlin
fun String.hexStringToByteArray() =
  chunked(2).map { it.toInt(16).toByte() }.toByteArray()
fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
fun ByteArray.xor(other: ByteArray) =
  (zip(other) { a, b -> (a.toInt() xor b.toInt()).toByte() }).toByteArray()

// md5, sha1, sha256 of the package's signature
// obtained by running https://github.com/warren-bank/print-apk-signature
// on the split apk
val PackageSignatures = arrayOf(
  "3f45f90cbcc718e4b63462baeae90c86",
  "1be2103a6929b38798a29d89044892f3b3934184",
  "1d32dbcf91697d46594ad689d49bb137f65d4bb8f56a26724ae7008648131b82"
)

// md5, sha1, sha256 of libjackpot-core.so
val JackpotSignatures = arrayOf(
  "81ec95e20a695c600375e3b8349722ab",
  "5a3cb86aa9b082d6a1c1dfa6f73dd431d7f14e18",
  "66370b8c96de7266b02bfe17e696d8a61b587656a34b19fbb0b2768a5305dd1d"
).map { it.hexStringToByteArray() }

// md5, sha1, sha256 of libil2cpp.so
val Il2CppSignatures = arrayOf(
  "67f969e32c2d775b35e2f2ad10b423c1",
  "c4387c429c50c4782ab3df409db3abcfa8fadf79",
  "d30568d1057fecb31a16f4062239c1ec65b9c2beab41b836658b637dcb5a51e4"
).map { it.hexStringToByteArray() }

@ExperimentalUnsignedTypes
fun assetStateLogGenerateV2(randomBytes64: String): String {
  val libHashChar = (randomBytes64[0].toInt() and 1) + 1
  val libHashType = randomBytes64[libHashChar].toInt().rem(3)
  val pkgHashChar = 2 - (randomBytes64[0].toInt() and 1)
  val pkgHashType = randomBytes64[pkgHashChar].toInt().rem(3)
  val xoredHashes =
    JackpotSignatures[libHashType].xor(Il2CppSignatures[libHashType])
      .toHexString()
  val packageSignature = PackageSignatures[pkgHashType]
  val signatures = when (randomBytes64[0].toInt() and 1) {
    0 -> "$xoredHashes-$packageSignature"
    1 -> "$packageSignature-$xoredHashes"
    else -> "$xoredHashes-$packageSignature"
  }
  println(signatures)
  var xorkey =
    (randomBytes64[0].toByte().toUInt() or
    (randomBytes64[1].toByte().toUInt() shl 8) or
    (randomBytes64[2].toByte().toUInt() shl 16) or
    (randomBytes64[3].toByte().toUInt() shl 24)) xor 0x12d8af36u
  var a = 0u
  var b = 0u
  var c = 0x2bd57287u
  var d = 0u
  var e = 0x202c9ea2u
  var f = 0u
  var g = 0x139da385u
  var h = 0u
  var i = 0u
  var j = 0u
  var k = 0u
  repeat(10) {
    h = g
    i = f
    j = e
    k = d
    g = c
    f = b
    a = ((a shl 11) or (xorkey shr 21)) xor a
    xorkey = (xorkey shl 11) xor xorkey
    c = ((g shr 19) or (k shl 13)) xor xorkey xor g xor ((xorkey shr 8) or (a shl 24))
    d = (k shr 19) xor a xor k xor (a shr 8)
    xorkey = j
    a = i
    b = k
    e = h
  }
  val xorBytes = ByteArray(signatures.length)
  for (index in 0..signatures.length - 1) {
    a = g
    xorkey = f
    b = ((i shl 11) or (j shr 21)) xor i
    j = (j shl 11) xor j
    e = ((c shr 19) or (d shl 13)) xor j xor c xor ((j shr 8) or (b shl 24))
    xorBytes[index] = e.toByte()
    f = k
    g = c
    k = d
    j = h
    i = xorkey
    c = e
    d = (d shr 19) xor b xor d xor (b shr 8)
    h = a
  }
  return base64Encoder.encodeToString(signatures.toByteArray().xor(xorBytes))
}
```

and here is a test with known values grabbed from the game. it produces
the exact same output

```
# running
random bytes: CB7tjOEZK6IQJrX93O0BuTjM5txYFmFO8sv1Pq9eAcE=

3f45f90cbcc718e4b63462baeae90c86-9e04c42835e046ae8b7200e66a8e7ffe7f0b9161
0fd36d6349f7a06c4a8e169a26d0010dc12bb77c50ea4579823c03f6498a4c6f52a6ba6bb4737b633f2f5077d9a62b161c6de5814d8b878dc42c620e58850a3774b70bc071dc1554d3

expected:
3f45f90cbcc718e4b63462baeae90c86-9e04c42835e046ae8b7200e66a8e7ffe7f0b9161
0fd36d6349f7a06c4a8e169a26d0010dc12bb77c50ea4579823c03f6498a4c6f52a6ba6bb4737b633f2f5077d9a62b161c6de5814d8b878dc42c620e58850a3774b70bc071dc1554d3
```

I spent some time mapping a bunch of the json responses. the
`Serialization$$Deserialize*` functions tell you all about which fields
each object has and which ones are optional. very relaxing activity

I also had to fight gson to override its builtin map serializer since
sifas maps are laid out as `[key, value, key, value, ...]` . it was not
a fun experience working with the generics hell that is java/kotlin

another thing I noticed is that the first hash in the response array is
actually what's being used as MasterVersion, so I'll stop hardcoding it.
instead, you're supposed to send a
`/dataLink/fetchGameServiceDataBeforeLogin` call without MasterVersion

next is the terms of service check. nothing special, it sends the current
version accepted (from the LoginResponse) and gets back the current terms
of service version. the response is a LoginResponse but with a lot of the
data omitted

... except it 403's for some reason. most likely something changes the
sessionKey after the login request. I remember seeing a method named
SessionEncrypt that takes the first 16 bytes of the sessionKey and
does some stuff with rijndael. let's take a look at it

it's using a lot of virtual function calls

```c
  rijndaelManaged = (int *)thunk_FUN_008ae738(Class$System.Security.Cryptography.RijndaelManaged);
  RijndaelManaged$$.ctor(rijndaelManaged,0);
...
  uVar1 = DMHttpApi$$CopySessionKey(0x10);
...
  (**(code **)(*rijndaelManaged + 0x128))
            (rijndaelManaged,uVar1,*(undefined4 *)(*rijndaelManaged + 300));
  (**(code **)(*rijndaelManaged + 0x198))(rijndaelManaged,*(undefined4 *)(*rijndaelManaged + 0x19c))
  ;
  piVar2 = (int *)(**(code **)(*rijndaelManaged + 0x170))
                            (rijndaelManaged,*(undefined4 *)(*rijndaelManaged + 0x174));
  uVar1 = (**(code **)(*rijndaelManaged + 0x110))
                    (rijndaelManaged,*(undefined4 *)(*rijndaelManaged + 0x114));

...
```

let's scroll down for clues.

since it says ICryptoTransform, I guessed this is the call to one of
the transform methods of the encryptor

```c
pTransformBlock = (code **)FUN_0086a584(encryptor,Class$System.Security.Cryptography.ICryptoTransform,5);
encryptedBytes = (**pTransformBlock)(encryptor,bytes,0,numBytes,pTransformBlock[1]);
```

let's look at the docs for ICryptoTransform.
the signature for TransformBlock is:

```
public byte[] TransformFinalBlock (byte[] inputBuffer, int inputOffset, int inputCount);
```

that matches, and the last parameter is a decompilation error. this also
tells me that what i named `bytes` is our standard `Array` struct we've
used in other hooks

so, are the 16 bytes of the sessionKey the IV or the Key? it's tricky
to tell, the IV has to be 16 bytes, but the key can also be 16 bytes

also, I can't find any x-refs to this so let's hook it and see where it's
being called from

very interesting. it seems that this is not what I thought it was.
it appears to be encrypting values in memory, specifically important
in-game things. it's called as soon as you start a live and the call is the
second last `Int::set_Value` here:

```c
void BuffInfo$$.ctor(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5)

{
  undefined4 uVar1;
  int iVar2;
  
  if (DAT_03708177 == '\0') {
    FUN_00871ed4(0x1d99);
    DAT_03708177 = '\x01';
  }
  Object$$.ctor(param_1,0);
  uVar1 = thunk_FUN_008ae738(Class$LLAS.ObfuscatedTypes.Int);
  Int$$.ctor(uVar1,0,0);
  *(undefined4 *)(param_1 + 8) = uVar1;
  uVar1 = thunk_FUN_008ae738(Class$LLAS.ObfuscatedTypes.Int);
  Int$$.ctor(uVar1,0,0);
  *(undefined4 *)(param_1 + 0xc) = uVar1;
  uVar1 = thunk_FUN_008ae738(Class$LLAS.ObfuscatedTypes.Int);
  Int$$.ctor(uVar1,0,0);
  *(undefined4 *)(param_1 + 0x10) = uVar1;
  uVar1 = thunk_FUN_008ae738(Class$LLAS.ObfuscatedTypes.Int);
  Int$$.ctor(uVar1,0,0);
  iVar2 = *(int *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = uVar1;
  if (iVar2 == 0) {
    FUN_0089d750(0);
  }
  Int$$set_Value(iVar2,param_2,0);
  iVar2 = *(int *)(param_1 + 8);
  if (iVar2 == 0) {
    FUN_0089d750(0);
  }
  Int$$set_Value(iVar2,param_3,0);
  iVar2 = *(int *)(param_1 + 0x10);
  if (iVar2 == 0) {
    FUN_0089d750(0);
  }
  Int$$set_Value(iVar2,param_4,0);
  iVar2 = *(int *)(param_1 + 0x14);
  if (iVar2 == 0) {
    FUN_0089d750(0);
  }
  Int$$set_Value(iVar2,param_5,0);
  return;
}
```

well, I'm not really interested in this, so this is a dead end for now.
gotta figure out why my terms of service request isn't being accepted

oh I'm stupid, there's a session key right in the login response! and it
gets xored in `DMHttpApi.__c__DisplayClass14_1$$_Login_b__1`

what it gets xored with is likely either the old sessionKey or the same
randomBytes that are xored with the startup auth key

and sure enough, it's the random bytes that are used to make the login
mask in `DMHttpApi.__c__DisplayClass14_0$$_Login_b__0`

seeing how not many other places call randomBytes I'm inclined to think
this is similar to how old SIF worked and that I should hold onto those
random bytes and only regenerate on startup/login

there we go, we are truly logged in now, that was a brainlet moment

so the next request is `/userProfile/setProfile` which sets name and
nickname, but most interestingly it contains a field called `device_token`

let's look at the `SetUserProfileRequest` constructor and the device
token getter

```c
void SetUserProfileRequest$$.ctor
               (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
               undefined4 param_5)

{
  Object$$.ctor(param_1,0);
  *(undefined4 *)(param_1 + 8) = param_2;
  *(undefined4 *)(param_1 + 0xc) = param_3;
  *(undefined4 *)(param_1 + 0x10) = param_4;
  *(undefined4 *)(param_1 + 0x14) = param_5;
  return;
}

void SetUserProfileRequest$$set_DeviceToken(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x14) = param_2;
  return;
}
```

okay, so param 5 of the constructor is the device token. what calls the
constructor?

```c
void UserProfileDM$$SetName
               (undefined4 param_1,undefined4 deviceToken,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  if (DAT_037070ef == '\0') {
    FUN_00871ed4(0xbdc0);
    DAT_037070ef = '\x01';
  }
  iVar1 = thunk_FUN_008ae738(Class$UserProfileDM.__c__DisplayClass5_0);
  Object$$.ctor(iVar1,0);
  if (iVar1 == 0) {
    FUN_0089d750(0);
    _DAT_00000008 = param_3;
    FUN_0089d750(0);
  }
  else {
    *(undefined4 *)(iVar1 + 8) = param_3;
  }
  *(undefined4 *)(iVar1 + 0xc) = param_4;
  iVar2 = UserProfileDM$$CheckInputTextLength(1,param_1);
  if (iVar2 == 1) {
    iVar2 = thunk_FUN_008ae738(Class$DotUnder.SVAPI.SetUserProfile);
    SetUserProfile$$.ctor(iVar2,0);
    uVar3 = thunk_FUN_008ae738(Class$DotUnder.Structure.SetUserProfileRequest);
    SetUserProfileRequest$$.ctor(uVar3,param_1,0,0,deviceToken,0);
...
```

(the last zero param is a decompilation error)

great, so what passes the deviceToken to SetName?

```c
void TutorialDM$$SetUserName(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = PushNotificationDM$$GetDeviceToken(0);
  UserProfileDM$$SetName(param_1,uVar1,param_2,param_3,0);
  return;
}
```

would you look at that

let's see where this leads us

```c
int PushNotificationDM$$GetDeviceToken(void)

{
  int iVar1;
  
  if (DAT_03706971 == '\0') {
    FUN_00871ed4(0x7da8);
    DAT_03706971 = '\x01';
  }
  iVar1 = ASLocalStorage$$get_PushNotificationDeviceToken(0);
  if (iVar1 == 0) {
    iVar1 = StringLiteral_73;
  }
  return iVar1;
}

undefined4 ASLocalStorage$$get_PushNotificationDeviceToken(void)

{
  int iVar1;
  undefined4 uVar2;
  
  if (DAT_037093a3 == '\0') {
    FUN_00871ed4(0x91);
    DAT_037093a3 = '\x01';
  }
  if (((*(byte *)(Class$DotUnder.LocalStorage + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
    FUN_0087f930();
  }
  iVar1 = LocalStorage$$HasKey("PushNotificationDeviceToken",0);
  if (iVar1 == 1) {
    if (((*(byte *)(Class$DotUnder.LocalStorage + 0xbf) & 2) != 0) &&
       (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
      FUN_0087f930();
    }
    uVar2 = LocalStorage$$GetString("PushNotificationDeviceToken",StringLiteral_73,0);
    return uVar2;
  }
  return 0;
}
```

cool, so it's in local storage. is there anything that actyally sets it?
let's check other ASLocalStorage methods

there is

```c
void ASLocalStorage$$set_PushNotificationDeviceToken(int param_1)

{
  if (DAT_037093a4 == '\0') {
    FUN_00871ed4(0xf5);
    DAT_037093a4 = '\x01';
  }
  if (param_1 != 0) {
    if (((*(ushort *)(Class$DotUnder.LocalStorage + 0xbe) & 0x200) != 0) &&
       (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
      FUN_0087f930();
    }
    LocalStorage$$SetString("PushNotificationDeviceToken",param_1,0);
    return;
  }
  if (((*(ushort *)(Class$DotUnder.LocalStorage + 0xbe) & 0x200) != 0) &&
     (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
    FUN_0087f930();
  }
  LocalStorage$$DeleteKey("PushNotificationDeviceToken",0);
  return;
}

void PushNotificationDM$$SetDeviceToken(undefined4 param_1)

{
  ASLocalStorage$$set_PushNotificationDeviceToken(param_1,0);
  return;
}

void PushNotification.__c$$_InitializeFirebaseMessaging_b__7_0
               (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  if (DAT_03704bd7 == '\0') {
    FUN_00871ed4(0xaff0);
    DAT_03704bd7 = '\x01';
  }
  if (param_3 == 0) {
    FUN_0089d750(0);
  }
  uVar1 = TokenReceivedEventArgs$$get_Token(param_3,0);
  uVar1 = String$$Concat("FirebaseMessaging:-Token-Received:",uVar1,0);
  uVar2 = FUN_010fe368(Method$Array.Empty()_object_);
  if (((*(byte *)(Class$LLAS.LLogger + 0xbf) & 2) != 0) &&
     (*(int *)(Class$LLAS.LLogger + 0x70) == 0)) {
    FUN_0087f930();
  }
  LLogger$$Debug(uVar1,uVar2,0);
  if (param_3 == 0) {
    FUN_0089d750(0);
  }
  uVar1 = TokenReceivedEventArgs$$get_Token(param_3,0);
  PushNotificationDM$$SetDeviceToken(uVar1,0);
  return;
}
```

hmm. it seems to be a standard token for push notifications obtained
through firebase. I wonder if they actually check it. I doubt it, but if
it's not too hard I would like to get a valid one

in base.apk/assets/google-services-desktop.json we can find the
firebase info

```json
{
  "project_info": {
    "project_number": "304268967066",
    "firebase_url": "https://all-stars-dev-91501190.firebaseio.com",
    "project_id": "all-stars-dev-91501190",
    "storage_bucket": "all-stars-dev-91501190.appspot.com"
  },
  "client": [
    {
      "client_info": {
        "mobilesdk_app_id": "1:304268967066:ios:fc1a9b49d6829936",
        "android_client_info": {
          "package_name": "com.Company.ProductName"
        }
      },
      "oauth_client": [
        {
          "client_id": "304268967066-e3n2no1402f89rqub55u0c7jrhhj4o3d.apps.googleusercontent.com"
        }
      ],
      "api_key": [
        {
          "current_key": "AIzaSyBAehda1QFNwi2g9U4FcT7m8lF8NPAdikg"
        }
      ],
      "services": {
        "analytics_service": {
          "status": 0
        },
        "appinvite_service": {
          "status": 0
        }
      }
    }
  ],
  "configuration_version": "1"
}
```

using `push-receiver` in nodejs and the `project_number` for sifas you can
get what look like valid push notification tokens:

```js
const { register, listen } = require('push-receiver');

(async () => {
  credentials = await register(304268967066);
  console.log(credentials)
})().catch(e => {
  console.log(e)
});
```

the token should be the fcm one

it was hard to find anything else that could do this in other langs and
I'm not up for implementing firebase protocol, but yeah, this should be
how you get 100% real tokens. or just send it empty, it shouldn't be
mandatory

all fields in setProfile are optional and it calls it multiple times, once
for name and once for nickname, always providing the device token

name and nickname must be 10 characters max. I keep them alphanumeric, but
I think spaces are allowed in both. if you enter an invalid name, the
server responds with error 500

the response is once again a LoginResponse

next request is `/userProfile/setProfileBirthday` . nothing special here,
just send month and day

next up is `/story/finishUserStoryMain` . I think this is sent when you
skip the cutscene after setting your name. again nothing special, the only
dubious part is how `is_auto_mode` is determined, but it might be on
a per-chapter basis and stored in the game's database

the response contains a `user_model_diff` field which is a UseModel object
just like in the LoginResponse, but most likely only contains changed
fields. maybe those other smaller LoginResponses work like this

next up is `/live/start`, which as the name suggests starts a live. as
with old sif, you can pick a partner and the partner user id is sent here.
the response contains literally the entire map - all the note timings and
other things

after the live start request, it sends a saveRuleDescription request
with a rule description id that was added to the user model after the
finishUserStoryMain request. this changes its `display_status` from 1 to 3.
no idea what this means but we could speculate it's the story progression
status of each chapter

I also figured out that the "LoginResponse" responses for terms and the
other non-login requests is actually called UserModelResponse and only
expects `user_model`

so it seems that the game freezes when i start a live while it's hooked.
I think this might be because the lib I am hooking from is being reloaded
or something, resulting in hooks jumping to deallocated memory. need to
investigate how to properly uninstall hooks when the library is unloaded

nevermind, after looking at the log it seems simpler - looks like we're
missing an export

```
10-25 22:34:46.166  9776  9801 E Unity   : EntryPointNotFoundException: Unable to find an entry point named 'NativeInputPollTouches' in 'KLab.
NativeInput.Native'.
10-25 22:34:46.166  9776  9801 E Unity   :   at KLab.NativeInput.LowLevel.NativeTouchQueue.Dll_PollTouches (System.Void* result, System.Int32
resultLength, System.Int32& anyRemaining) [0x00000] in <00000000000000000000000000000000>:0
10-25 22:34:46.166  9776  9801 E Unity   :   at KLab.NativeInput.LowLevel.NativeTouchQueue.PollTouches () [0x00000] in <00000000000000000000000000000000>:0
10-25 22:34:46.166  9776  9801 E Unity   :   at KLab.NativeInput.LowLevel.NativeTouchQueue.GetLatestTouches (System.Collections.Generic.List`1
[T] result) [0x00000] in <00000000000000000000000000000000>:0
10-25 22:34:46.166  9776  9801 E Unity   :   at LLAS.Scene.Live.Game.TouchInputBroadcaster.RefreshInput () [0x00000] in <000000000000000000000
00000000000>:0
```

let's add all the `NativeInput*` exports

yep, doesn't crash anymore now. time to log and implement more requests

once you complete a song, the game sends note-by-note scoring to
/live/finish , but I'm not gonna bother emulating that for now. for the
tutorial lives, you can skip and it will send all notes with 0 score

the `live_id` in this request is interesting. you get it from the live start
request response and it's an unusually large number.

I'm 99% sure the first few digits are the timestamp, but I don't know if
the whole thing is a really high resolution timestamp or if it's 2
values combined. doesn't really matter, because we don't need to compute
it, I just thought it seemed interesting.

so, for the result dict we get the note id's from the live start response
and set them all to judge type 1, voltage 0, card master id 0

`wave_stat` dict should match the `live_wave_settings` from the live start
request. I think this is always set to all false's when skipping

the `turn_stat_dict` seems also all zero'd, except for the first note.
we need to calculate or hardcode `current_life` for this first note.
I'll hardcode it for now

not sure where `target_score` comes from, I'll hardcode it for now. we
only need to skip the 2 tutorial lives anyway

somehow, skipping submits the score as a "perfect" live and even full combo

live power, yet another value to hardcode or learn to calculate from the
team info

for the card stat dict, it's just the card id's from `user_live_deck_by_id`
with all zero vals

interestingly, at the end of turn stat dict we have notes 0 and 55 which
are technically out of bounds and note 0 has current life set like note 1.
this pattern repeats in different songs

next up we just have another story complete request and another live skip,
nothing to see here. also another saveRuleDescription, this time with id
2 (previous one was id 1)

then there's the favorite character selection,
`/communicationMember/setFavoriteMember` . straightforward request,
nothing to see. seems to return a UserModelResponse

`/bootstrap/fetchBootstrap` : this request seems to get an user model diff
with only the info requested in the `bootstrap_fetch_types` field. i might
map these types out later, for now let's just request what the game
requests. device name is also sent to the server here. no big deal, we can
just make a list of known devices. types are `[2,3,4,5,9,10]` in this
particular request. note that this is not a normal UserModelResponse.
it has some extra fetch bootstrap fields

I found a list of valid device names here https://support.google.com/googleplay/answer/1727131?hl=en-GB

this is how the game gets the device name: https://docs.unity3d.com/ScriptReference/SystemInfo-deviceModel.html
which would be the 4th column of the csv above

I also noticed that the device_name was only introduced after the first
few updates, the first binary I dumped didn't have it

`/navi/tapLovePoint` : this is sent when you touch your waifu and get love
points, it contains the same character id used in setFavoriteMember and
returns what looks like a UserModelResponse

`/navi/saveUserNaviVoice` : this takes some id (100010004) that doesn't
seem to come from previous responses and returns a UserModelResponse.
it's used to refresh the voices map in the UserModel. not sure what those
voices do, maybe it just updates which menus are unlocked?

`/trainingTree/fetchTrainingTree` and `/trainingTree/levelUpCard` are
for the tutorial on leveling up your card. nothing special, you just need
your card master id

`/trainingTree/activateTrainingTreeCell` I think this is when you do
the member training and spend your AP? not sure where the cell id's come
from, at first I thought it was member master id's but nope, in the user
model they go from 1-9 and then jump to like 101+

`/card/updateCardNewFlag` I think this updates the two awakening booleans
in the user model's card info, which switched to true after the training.
again, this returns a UserModelResponse

`/communicationMember/finishUserStorySide` this is probably when you get
the dialogue with your waifu. similar to the main story finish request,
nothing to see here

`/liveDeck/saveDeckAll` and `/liveDeck/saveSuit` , I guess this is where
you set up your live team. I think the `squad_dict` is the three teams
you can switch between, but I can't figure out what `card_with_suit`
signifies. it's a map of card id's to either null or their suit id which
is the same as the card id. maybe suit is the outfit? well, I don't need to
understand anyway for now, I just hardcode the default team the tutorial
picks for me

note that it's important to update our usermodel at this request so that
our team is correct in the next live finish requests

`/livePartners/fetch` empty request, returns a list of partners before
starting the live

while looking at this request I found something pretty funny, they typo'd
"Partners" in the response class name

```c
  FetchLiveParntersResponse$$.ctor(iVar1,0);
  if (((*(byte *)(Class$DotUnder.Serialization + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.Serialization + 0x70) == 0)) {
    FUN_0087f930();
  }
  piVar2 = (int *)Serialization$$TryGetValue(param_1,"partner_select_state");

...
```

then we have another live start/finish, live partner id is zero

`/gacha/fetchGachaMenu` empty request, this is the scouting tutorial and
this retrieves the list of scouting pools

`/gacha/draw` is nothing special, you just pass it the gacha id from the
`gacha_draws` field in the previous request

yet another fetchBootstrap request, with the same id's as the first one

`/tutorial/phaseEnd` this concludes the tutorial. empty request, returns a
UserModelResponse

then it calls `/dataLink/fetchGameServiceData` which is similar to the
request it does at the very beginning, however I noticed it does some
interesting stuff with the response in
`PlatformGameServiceDM.__c__DisplayClass1_1$$_FetchState_b__1`

```c
    iVar2 = FetchGameServiceDataResponse$$get_Data(param_2,0);
    if (iVar2 == 0) {
      FUN_0089d750(0);
    }
    uVar3 = UserLinkData$$get_AuthorizationKey(iVar2,0);
    if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
       (*(int *)(Class$System.Convert + 0x70) == 0)) {
      FUN_0087f930();
    }
    uVar3 = Convert$$FromBase64String(uVar3,0);
    uVar5 = Lib$$XorBytes(uVar5,uVar3,0);
    if (iVar1 == 0) {
      FUN_0089d750(0);
    }
    UserLinkData$$set_ServiceUserCommonKey(iVar1,uVar5,0);
    iVar1 = *(int *)(param_1 + 0xc);
    if (iVar1 == 0) {
      FUN_0089d750(0);
    }
```

it seems that `service_user_common_key` is actually set client-side by
xoring `authorization_key` with something. most likely the random bytes
from the mask sent with the request. after checking, I noticed that it
also does this with FetchStateBeforeLogin. seems like it's saved as the
PW field in local storage in `UserKey$$SetIDPW` in
`PlatformGameService$$Migrate`. this PW is then retrieved on login,
and passed to `DMHttpApi.__c__DisplayClass14_0$$_Login_b__0` as third
param, which means this is our sessionKey for subsequent login requests

well, we have a bit of a problem here. my fetchGameServiceData request
with the random service id doesn't return anything here, however you might
remember that when the game receives the startup response it does the same
`UserKey$$SetIDPW` call, which might mean that this authorization key is
just the one from when we called startup. either way, I want to investigate
whether I'm missing a request that associates the account with my service
id or if it's just doing that because it's an invalid service id

yep, seems like I was missing a `/dataLink/linkOnStartUpGameService` call,
all good. let's move to the next request

fetchBootstrap call with types 2,3,4,5,9,10,11 . this returns a list
of login bonuses in `fetch_bootstrap_login_bonus_response` .

`/loginBonus/readLoginBonus` called once for each login bonus id, empty
response. I guess this marks the various login bonus splashscreens as read.

seems like it's called on `event_2d_login_bonuses` with type 3,
`beginner_login_bonuses` with type 2, `login_bonuses` with type 1. not
sure what happens with the other 3 pools of login bonuses

then we have another saveUserNaviVoice call with id's 100010123, 100010113
and a fetchBootstrap with the usual id's

`/notice/fetchNoticeDetail` this is called on one of the `super_notices` .
from fetchBootstrap. the way it picks which super notice id to use is

```c
void HomeDM$$GetSuperNoticeDetailMasterId(void)

{
  undefined4 uVar1;
  
  if (DAT_03706ed3 == '\0') {
    FUN_00871ed4(0x4de5);
    DAT_03706ed3 = '\x01';
  }
  uVar1 = NoticeDM$$GetUnreadSuperNoticeIds(0);
  FUN_010f5084(uVar1,Method$Enumerable.LastOrDefault()_int_);
  return;
}
```

which means it gets the last in the list

`/notice/fetchNotice` empty request, it just gets news and whatnot

another saveUserNaviVoice with id's 100010105,100010038,100010018

`/present/fetch` call, empty request. gets a list of pending presents

saveRuleDescription with id 20

`/present/receive` with a list of id's from `/present/fetch` to claim all
gifts

yet another fetchBoostrap call with types 2,3,4,5,9,10

... and that's it, that's pretty much all you need to start a new account,
log in, complete the tutorial and get your daily rewards. this pretty much
concludes what I wanted to achieve for the time being, but I will update
this article whenever I find anything interesting

you can check out my client here and use it as a reference for your own
https://github.com/Francesco149/todokete

# a look at the assets

I was looking to extract some assets from the game. not sure if this is
standard unity asset packaging but here's how they're laid out

`data/data/com.klab.lovelive.allstars/files/files` contains a plain text
file named `fe12c8ba-04b2-41b6-b1af-ffee5ee59c43`. this probably changes
for each build. it contains a map of assets to sha-1 hashes:

```
1
card:100011001  eb73a5908f31c052f9432b37aab01b0614b699ae
card:100011002  245b5bd66c1918d963348fcbcc14d3273b8ba46e
card:100012001  6ba14134894fd894c811ce7fde599d76eb8d3d9f
card:100013001  a30cfa2da9e1b74443d5460f333c09eb33a39198
card:100021001  af7d4f64e1fc4cc64ace920c0fb297304e3fb8ab
card:100021002  c7fc1ff28d960c32bab8612ba45d130ba37c783a

....


live:1000101  97fadca11fac62bc200b4ce77a0120ac594c33cd
live:1000102  51dda48f13b89fab1163b07eec1cf51caa427d66
live:1000103  614f5b6f9462fdcdcda75dc57fd13b84963e6490
live:1000201  420a0779aa8dfcb053bb59e680db1067891c4f91
live:1000202  41c8f8417c090c2c2ad1e523cc19dc8286d67510
live:1000203  eb8db1cf4dfae2551fbdf10eabd178a4712e313e
live:1000401  a350bc00e678a4d16bd7dc15e36823047f4b1c45

...

love:101_10 d3631e84fa5f19443c0db73ff17d65ede5c7a49c
love:101_20 840d74373ff6f226c00f0f4661719167147d9d34
love:101_30 e4004a4444c703c5691e9bb286790c1f170a2929
love:101_40 7bffbefd74c7e5da7b41282f85cdeba227e3bebc
love:101_50 fe37eb04c5d58cd83a09d819ad7953b26d6fcff0
love:102_10 2836059242bf615daf4a36dd64eb990e020cb102
love:102_20 f81e912c293e1967ea62de4a29f27e058c93d04a
love:102_30 befb476da8ee0be8dd5209af56e91547296ff2c2

...

main  6c84c160fe1b5b2834c0b07d5685bd21902d757b
music:10001 7c20bbff2d642da68b7956f8288b0ceddfb559c5
music:10002 6c942bfbd7818f1d3ff03894396224eb6280f9bb
music:10004 ad9c64e29a822d51af5a4983abb11f23f9414cfa
music:10005 1f1fc9cc0b9ee042b7c0594e4c9e760200f7f319
music:10011 1f282efa1d9e04303a2410efd615f391d311db3a
music:10014 ab230a60f63d353b54f1a60624f2ef6909233b63
music:10015 415ba87cc3aa0e1d89e06991893d6a63e135af80
music:10016 af02ed318a935f64e943586d53039583466f7f85

...

op  f73a0a9fee3ae140878114a3e88702e5efb3fddd
story-voice:ES/0002/es_0002_01  9c5f38f7b76bf38244094f29f8c085e89de9abef
story-voice:ES/0002/es_0002_02  96c026d971b20de5f43543389d844ccddb34ca43
story-voice:ES/0002/es_0002_03  5118b9ac408ed0aad1841d2b6ed62488d61fd03d
story-voice:ES/0002/es_0002_04  6d93f972fccccbaedaa0515f5cbd0cd7c253f188
story-voice:ES/0002/es_0002_05  c68d4cb4eea1811f5a8fdf1af1cef47abf41778c
story-voice:ES/0002/es_0002_06  49de9ef73e44512311b17c65e18b58ceda7bedb6
story-voice:ES/0002/es_0002_07  34e3841eb8306cc11258fe836e10e14bdd58e98c
story-voice:MES/0001/mes_0001_01  36804fd9971c80b461cab9c5f8d953d0fe8a2272
story-voice:MES/0001/mes_0001_02  028781c7b118237070bf7fdc5504f59aedd80fa9
story-voice:MES/0001/mes_0001_03  e4e6cda8dba865379831922b073a0b2709568cf9
story-voice:MES/0001/mes_0001_04  893560c1540e1c0355d2794d4d2c557ef62fcf52

...

suit:100011001  00a503790212b6aa66b0a666c98e45ea02c5ba35
suit:100012001  1d05237d863d748e68d034a1152e0ca6fc346f90
suit:100013001  98d5ba50cc24b6005b38f5c13fabeb89ffd6e049
suit:100021001  65fe1540c0b1d7fe8db6ae9b8b77bffdc5bf4037
suit:100022001  cc239b4857ecda8aea5a40a73b9acf4cd0cf476a
suit:100023001  ad3cafaf92fc9d995418fbcc1896039fd7495a98
suit:100031001  1d829f5a4e93aa166887d181c33ecdd75254a0bd
suit:100032001  e5aff74749b4bc2f90c45484117bf3b42d9546b4
suit:100033001  7907ae9e67e50ff3b883993be481b2b3aa7f5b4c

...

```

i see there's a file that starts with masterdata.db, let's search for this
string in the game's binary

sure enough, it seems to be some kind of custom encrypted database,
a function named ```Sqlite$$Open``` references that string

```c
  iVar1 = Sqlite$$HasDefaultDb();
  if (iVar1 == 1) {
    Cache$$Clear(0);
    Cache$$ClearShortLife(0);
    if (((*(byte *)(Class$DotUnder.MasterData + 0xbf) & 2) != 0) &&
       (*(int *)(Class$DotUnder.MasterData + 0x70) == 0)) {
      FUN_0087f998();
    }
    uVar2 = MasterData$$DbPath("masterdata.db",0);
    uVar3 = MasterData$$GetSqliteKey("masterdata.db",0,0);
    if (((*(byte *)(Class$DotUnder.Sqlite + 0xbf) & 2) != 0) &&
       (*(int *)(Class$DotUnder.Sqlite + 0x70) == 0)) {
      FUN_0087f998();
    }
    Sqlite$$Add("defaultdb",uVar2,uVar3);
    if (param_1 == 0) {
      FUN_0089d7b8(0);
    }
```

ok so it just seems to be a random 32-bytes key generated and stored
in the shared prefs xml

```c
undefined4 MasterData$$GetSqliteMasterKey(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  if (DAT_03704bde == '\0') {
    FUN_00871f3c(0x69b6);
    DAT_03704bde = '\x01';
  }
  if (((*(byte *)(Class$DotUnder.LocalStorage + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
    FUN_0087f998();
  }
  iVar1 = PlayerPrefs$$HasKey("SQ",0);
  if (iVar1 == 1) {
    if (((*(byte *)(Class$DotUnder.LocalStorage + 0xbf) & 2) != 0) &&
       (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
      FUN_0087f998();
    }
    uVar2 = PlayerPrefs$$GetString("SQ",StringLiteral_73,0);
    if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
       (*(int *)(Class$System.Convert + 0x70) == 0)) {
      FUN_0087f998();
    }
    uVar2 = Convert$$FromBase64String(uVar2,0);
    return uVar2;
  }
  if (((*(byte *)(Class$DotUnder.DMCryptography + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.DMCryptography + 0x70) == 0)) {
    FUN_0087f998();
  }
  uVar2 = DMCryptography$$RandomBytes(0x20,0);
  if (((*(byte *)(Class$System.Convert + 0xbf) & 2) != 0) &&
     (*(int *)(Class$System.Convert + 0x70) == 0)) {
    FUN_0087f998();
  }
  uVar3 = Convert$$ToBase64String(uVar2,0);
  if (((*(byte *)(Class$DotUnder.LocalStorage + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.LocalStorage + 0x70) == 0)) {
    FUN_0087f998();
  }
  LocalStorage$$SetString("SQ",uVar3);
  return uVar2;
}
```

it later calls "GetRawSqliteKey" and passes it "masterdata.db" and the
master key bytes

this appears to do a hmac-sha1 on the masterdata.db string using the
master key as the key

```c
  masterdataDbUtf8 =
       (**(code **)(*piVar2 + 0x148))(piVar2,masterdataDb,*(undefined4 *)(*piVar2 + 0x14c));
  if (((*(byte *)(Class$DotUnder.DMCryptography + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.DMCryptography + 0x70) == 0)) {
    FUN_0087f998();
  }
  local_28 = 0;
  sha1 = DMCryptography$$HmacSha1(masterdataDbUtf8,masterKeyBytes,0);
  sha1bytes = sha1 + 0x10;
```

it then allocates a 12-byte array made up of 3 uint's and copies the first
12 bytes of the hmac-sha1 hash to it, encoded as uint's

```c
  uintArray = InstantiateArray(Class$uint[],3);
  i = 0;
  do {
    j = 0;
    ithUint = (uint *)(uintArray + i * 4 + 0x10);
    do {
      if (uintArray == 0) {
        NullPointerExceptionMaybe(0);
      }
      if (*(uint *)(uintArray + 0xc) <= i) {
        masterdataDbUtf8 = IndexOutOfRangeException();
        Throw(masterdataDbUtf8,0,0);
      }
      shiftedUint = *ithUint << 8;
      *ithUint = shiftedUint;
      if (*(uint *)(uintArray + 0xc) <= i) {
        masterdataDbUtf8 = IndexOutOfRangeException();
        Throw(masterdataDbUtf8,0,0);
        shiftedUint = *ithUint;
      }
      if (sha1 == 0) {
        NullPointerExceptionMaybe(0);
      }
      if (*(uint *)(sha1 + 0xc) <= (uint)(k + j)) {
        masterdataDbUtf8 = IndexOutOfRangeException();
        Throw(masterdataDbUtf8,0,0);
      }
      orMask = (byte *)(sha1bytes + j);
      j = j + 1;
      *ithUint = shiftedUint | *orMask;
    } while (j != 4);
    i = i + 1;
    sha1bytes = sha1bytes + 4;
    k = k + 4;
  } while (i != 3);
  return uintArray;
```

later, in GetSqliteKey, it formats these 3 uint's as a string, separated
by dots

```c
  uintsKey = MasterData$$GetRawSqliteKey(masterdataDb,masterKeyBytes);
  if (uintsKey == 0) {
    NullPointerExceptionMaybe(0);
  }
  if (*(int *)(uintsKey + 0xc) == 0) {
    masterKeyBytes = IndexOutOfRangeException();
    Throw(masterKeyBytes,0,0);
  }
  uintsKeyData = *(undefined4 *)(uintsKey + 0x10);
  masterKeyBytes = FUN_008ae39c(Class$uint,&uintsKeyData);
  if (*(uint *)(uintsKey + 0xc) < 2) {
    secondUintClass = IndexOutOfRangeException();
    Throw(secondUintClass,0,0);
  }
  secondUint = *(undefined4 *)(uintsKey + 0x14);
  secondUintClass = FUN_008ae39c(Class$uint,&secondUint);
  if (*(uint *)(uintsKey + 0xc) < 3) {
    thirdUintClass = IndexOutOfRangeException();
    Throw(thirdUintClass,0,0);
  }
  thirdUint = *(undefined4 *)(uintsKey + 0x18);
  thirdUintClass = FUN_008ae39c(Class$uint,&thirdUint);
  String$$Format("{0}.{1}.{2}",masterKeyBytes,secondUintClass,thirdUintClass,0);
```

`Sqlite$$Add` calls OpenDB with the key string and the path of the db file
paired in a single string, separated by a dash

```c
void Sqlite$$Add(undefined4 param_1,undefined4 masterDataPath,undefined4 keyUintsString)

{
  undefined4 uVar1;
  int iVar2;
  
  if (DAT_0370745e == '\0') {
    FUN_00871f3c(0x9154);
    DAT_0370745e = '\x01';
  }
  if (((*(byte *)(Class$DotUnder.Sqlite + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.Sqlite + 0x70) == 0)) {
    FUN_0087f998();
  }
  Sqlite$$Remove(param_1);
  uVar1 = String$$Format("{0}-{1}",keyUintsString,masterDataPath,0);
  uVar1 = Sqlite$$OpenDB(uVar1,"klb_vfs");
  iVar2 = **(int **)(Class$DotUnder.Sqlite + 0x5c);
  if (iVar2 == 0) {
    NullPointerExceptionMaybe(0);
  }
  FUN_022e73e8(iVar2,param_1,uVar1,Method$Dictionary_string_-IntPtr_.Add());
  iVar2 = String$$op_Equality(param_1,"defaultdb",0);
  if (iVar2 != 1) {
    return;
  }
  if (((*(byte *)(Class$DotUnder.Sqlite + 0xbf) & 2) != 0) &&
     (*(int *)(Class$DotUnder.Sqlite + 0x70) == 0)) {
    FUN_0087f998();
  }
  *(undefined4 *)(*(int *)(Class$DotUnder.Sqlite + 0x5c) + 4) = uVar1;
  return;
}
```

it seems that `klb_vfs` is a vfs module for sqlite3:

```c
  if ((klbVfsString != 0) &&
     (iVar1 = *(int *)(Class$DotUnder.Sqlite + 0x5c), *(char *)(iVar1 + 8) == '\0')) {
    if (((*(byte *)(Class$DotUnder.Sqlite + 0xbf) & 2) != 0) &&
       (*(int *)(Class$DotUnder.Sqlite + 0x70) == 0)) {
      FUN_0087f998();
      iVar1 = *(int *)(Class$DotUnder.Sqlite + 0x5c);
    }
    *(undefined *)(iVar1 + 8) = 1;
    KLBVFS$$klbvfs_register(0);
  }
  local_1c = 0;
  keyPathPairUtf8 = StringExtensionMethods$$ToUtf8(keyPathPair,1);
  klbVfsStringUtf8 = StringExtensionMethods$$ToUtf8(klbVfsString,1);
  if (((*(byte *)(Class$Forfeit.Sqlite3 + 0xbf) & 2) != 0) &&
     (*(int *)(Class$Forfeit.Sqlite3 + 0x70) == 0)) {
    FUN_0087f998();
  }
  local_20 = Sqlite3$$sqlite3_open_v2(keyPathPairUtf8,&local_1c,1,klbVfsStringUtf8,0);
```

let's take a look at libklbvfs.so . it calls `sqlite3_vfs_find` with NULL
in `klbvfs_register` and assigns it to some global. then it calls
`sqlite3_vfs_register` on some other global. these globals actually overlap
and it's just one big `sqlite3_vfs` struct

sqlite doc:

```
The sqlite3_vfs_find() interface returns a pointer to a VFS given its name.
Names are case sensitive. Names are zero-terminated UTF-8 strings.
If there is no match, a NULL pointer is returned.
```

what happens if we pass null though?

```
If zVfsName is NULL then the default VFS is returned.
```

ok so it's just the default sqlite vfs

ok so this is the struct it's passing to vfs register:
https://www.sqlite.org/c3ref/vfs.html

we can map it out and see which function is which, and here's our register
function documented

I also mapped the `sqlite3_file` and `sqlite3_io_methods` structs which
are passed to these methods and documented here

https://www.sqlite.org/c3ref/file.html

https://www.sqlite.org/c3ref/io_methods.html


```c
void klbvfs_register(void)

{
  sqlite3_vfs_00012004.pAppData = (sqlite3_vfs *)sqlite3_vfs_find(0);
  DAT_00012080 = (sqlite3_vfs_00012004.pAppData)->szOsFile;
  sqlite3_vfs_00012004.szOsFile = DAT_00012080 + 0x10;
  sqlite3_vfs_register(&sqlite3_vfs_00012004,0);
  return;
}
```

ok, so it's most likely a thin layer over the default vfs

what's this szOsFile stuff though?

```
The szOsFile field is the size of the subclassed sqlite3_file structure
used by this VFS.
```

ok, so it's the default szOsFile + 16 for the klab vfs, let's rename it.
this also means that the `sqlite3_file` struct has 16 extra bytes at the
end which I will add as unknown fields


```c
void klbvfs_register(void)

{
  sqlite3_vfs_00012004.pAppData = (sqlite3_vfs *)sqlite3_vfs_find(0);
  g_defaultSzOsFile = (sqlite3_vfs_00012004.pAppData)->szOsFile;
  sqlite3_vfs_00012004.szOsFile = g_defaultSzOsFile + 0x10;
  sqlite3_vfs_register(&sqlite3_vfs_00012004,0);
  return;
}
```

now if we take a look at the struct memory region we can map out all the
unnamed functions it points to

```c
                             sqlite3_vfs_00012004.szOsFile                   XREF[1,2]:   klbvfs_register:00010620(*), 
                             sqlite3_vfs_00012004.pAppData                                klbvfs_register:0001060c(W), 
                             sqlite3_vfs_00012004                                         klbvfs_register:0001061c(W)  
        00012004 02 00 00        sqlite3_
                 00 00 00 
                 00 00 00 
           00012004 02 00 00 00     int       2h                      iVersion                          XREF[1]:     klbvfs_register:00010620(*)  
           00012008 00 00 00 00     int       0h                      szOsFile                          XREF[1]:     klbvfs_register:0001061c(W)  
           0001200c 00 04 00 00     int       400h                    mxPathname
           00012010 00 00 00 00     sqlite3_  00000000                pNext
           00012014 c4 0b 01 00     char *    s_klb_vfs_00010bc4      zName         = "klb_vfs"
           00012018 00 00 00 00     sqlite3_  00000000                pAppData                          XREF[1]:     klbvfs_register:0001060c(W)  
           0001201c 38 06 01 00     void *    FUN_00010638            xOpen
           00012020 20 07 01 00     void *    LAB_00010720            xDelete
           00012024 2c 07 01 00     void *    FUN_0001072c            xAccess
           00012028 7c 07 01 00     void *    FUN_0001077c            xFullPathname
           0001202c e8 07 01 00     void *    LAB_000107e8            xDlOpen
           00012030 f4 07 01 00     void *    LAB_000107f4            xDlError
           00012034 00 08 01 00     void *    LAB_00010800            xDlSym
           00012038 0c 08 01 00     void *    LAB_0001080c            xDlClose
           0001203c 18 08 01 00     void *    LAB_00010818            xRandomness
           00012040 24 08 01 00     void *    LAB_00010824            xSleep
           00012044 30 08 01 00     void *    LAB_00010830            xCurrentTime
           00012048 3c 08 01 00     void *    LAB_0001083c            xGetLastError
           0001204c 48 08 01 00     void *    LAB_00010848            xCurrentTime
           00012050 00 00 00 00     void *    00000000                xNextSystemC

```

let's take a look at xOpen

```c
int xOpen(sqlite3_vfs *vfs,char *zName,sqlite3_file *file,int flags,int *pOutFlags)

{
  sqlite3_io_methods **ppsVar1;
  int i;
  sqlite3_io_methods *local_28 [4];
  char firstChar;
  
  zName = zName + 1;
  i = 0;
  local_28[1] = (sqlite3_io_methods *)0x0;
  local_28[0] = (sqlite3_io_methods *)0x0;
  local_28[2] = (sqlite3_io_methods *)0x0;
  do {
    firstChar = zName[-1];
    if (firstChar == '.') {
      if (1 < i) {
        return 1;
      }
      i = i + 1;
    }
    else {
      if (9 < ((uint)(byte)firstChar - 0x30 & 0xff)) {
        if (i != 2 || firstChar != ' ') {
          return 1;
        }
        i = (*(code *)vfs->pAppData->xOpen)(vfs->pAppData,zName,file,flags,pOutFlags);
        ppsVar1 = (sqlite3_io_methods **)((int)&file->pMethods + g_defaultSzOsFile);
        *ppsVar1 = file->pMethods;
        ppsVar1[1] = local_28[0];
        ppsVar1[2] = local_28[1];
        ppsVar1[3] = local_28[2];
        file->pMethods = (sqlite3_io_methods *)0x11ecc;
        return i;
      }
      local_28[i] = (sqlite3_io_methods *)((uint)(byte)firstChar + (int)local_28[i] * 10 + -0x30);
    }
    zName = zName + 1;
  } while( true );
}
```

uh oh seems like the extra bytes at the end of the file structs are
confusing the decompiler, let's try to define them as a separate 16 byte
struct and retype ppsVar1 to it

```c
int xOpen(sqlite3_vfs *vfs,char *zName,sqlite3_file *file,int flags,int *pOutFlags)

{
  klbvfs_file *klbfile;
  int i;
  klbvfs_file newKlbfile;
  char firstChar;
  
  zName = zName + 1;
  i = 0;
  newKlbfile.unk1 = 0;
  newKlbfile.pMethods = (sqlite3_io_methods *)0x0;
  newKlbfile.unk2 = 0;
  do {
    firstChar = zName[-1];
    if (firstChar == '.') {
      if (1 < i) {
        return 1;
      }
      i = i + 1;
    }
    else {
      if (9 < ((uint)(byte)firstChar - 0x30 & 0xff)) {
        if (i != 2 || firstChar != ' ') {
          return 1;
        }
        i = (*(code *)vfs->pAppData->xOpen)(vfs->pAppData,zName,file,flags,pOutFlags);
        klbfile = (klbvfs_file *)((int)&file->pMethods + g_defaultSzOsFile);
        klbfile->pMethods = file->pMethods;
        *(sqlite3_io_methods **)&klbfile->unk1 = newKlbfile.pMethods;
        klbfile->unk2 = newKlbfile.unk1;
        klbfile->unk3 = newKlbfile.unk2;
        file->pMethods = (sqlite3_io_methods *)0x11ecc;
        return i;
      }
      (&newKlbfile.pMethods)[i] =
           (sqlite3_io_methods *)
           ((uint)(byte)firstChar + (int)(&newKlbfile.pMethods)[i] * 10 + -0x30);
    }
    zName = zName + 1;
  } while( true );
}
```

well that's still terrible but you can tell it's saving the default
pMethods pointer in the first field and zeroing the other 3 fields

then it replaces pMethods with a different table of functions, which
we can retype to `sqlite3_io_methods` and check out to map the methods

```c
                             //
                             // .data.rel.ro 
                             // SHT_PROGBITS  [0x1ecc - 0x1f17]
                             // ram: 00011ecc-00011f17
                             //
                             sqlite3_io_methods_00011ecc                     XREF[2]:     xOpen:00010700(*), 
                                                                                          _elfSectionHeaders::00000264(*)  
        00011ecc 03 00 00        sqlite3_
                 00 54 08 
                 01 00 6c 
           00011ecc 03 00 00 00     int       3h                      iVersion                          XREF[2]:     xOpen:00010700(*), 
                                                                                                                     _elfSectionHeaders::00000264(*)  
           00011ed0 54 08 01 00     void *    LAB_00010854            xClose
           00011ed4 6c 08 01 00     void *    LAB_0001086c            xRead
           00011ed8 3c 0a 01 00     void *    LAB_00010a3c            xWrite
           00011edc 54 0a 01 00     void *    LAB_00010a54            xTruncate
           00011ee0 6c 0a 01 00     void *    LAB_00010a6c            xSync
           00011ee4 84 0a 01 00     void *    LAB_00010a84            xFileSize
           00011ee8 9c 0a 01 00     void *    LAB_00010a9c            xLock
           00011eec b4 0a 01 00     void *    LAB_00010ab4            xUnlock
           00011ef0 cc 0a 01 00     void *    LAB_00010acc            xCheckReserv
           00011ef4 e4 0a 01 00     void *    LAB_00010ae4            xFileControl
           00011ef8 fc 0a 01 00     void *    LAB_00010afc            xSectorSize
           00011efc 14 0b 01 00     void *    LAB_00010b14            xDeviceChara
           00011f00 2c 0b 01 00     void *    LAB_00010b2c            xShmMap
           00011f04 44 0b 01 00     void *    LAB_00010b44            xShmLock
           00011f08 5c 0b 01 00     void *    LAB_00010b5c            xShmBarrier
           00011f0c 74 0b 01 00     void *    LAB_00010b74            xShmUnmap
           00011f10 8c 0b 01 00     void *    LAB_00010b8c            xFetch
           00011f14 a4 0b 01 00     void *    LAB_00010ba4            xUnfetch

```

it also does something weird with pMethods at the end, maybe the first char
is an index of some sort in that case

anyway, if we check out the replaced file methods we see that most of them
just pass through the call to the original methods

```c
void file_xClose(sqlite3_file *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00010864. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(*(int *)((int)&param_1->pMethods + g_defaultSzOsFile) + 4))();
  return;
}
```

in xRead we can see that it's doing funky stuff with constants used in
random number generators. this is gonna take a while to decipher

```c
int file_xRead(sqlite3_file *file,byte *dst,int iAmt,int64_t iOfst)

{
  uint uVar1;
  uint uVar2;
  ulonglong uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  sqlite3_io_methods *defaultMethods;
  void *defaultxRead;
  int iVar8;
  int iVar9;
  void *defaultxWrite;
  void *defaultxClose;
  
  iVar4 = (**(code **)(*(int *)((int)&file->pMethods + g_defaultSzOsFile) + 8))(file);
  if (iVar4 == 0) {
    iVar8 = 0x343fd;
    iVar5 = 0x269ec3;
    defaultMethods = (sqlite3_io_methods *)((int)&file->pMethods + g_defaultSzOsFile);
    defaultxClose = defaultMethods->xClose;
    if ((int)(iOfst._4_4_ - (uint)((int)iOfst == 0)) < 0) {
      iVar8 = 0;
      defaultxRead = defaultMethods->xRead;
      defaultxWrite = defaultMethods->xWrite;
      iVar5 = 1;
    }
    else {
      iVar7 = 1;
      iVar9 = 0;
      uVar3 = iOfst;
      do {
        if ((uVar3 & 1) != 0) {
          iVar9 = iVar7 * iVar5 + iVar9;
          iVar7 = iVar7 * iVar8;
        }
        uVar1 = (uint)(uVar3 >> 0x21);
        uVar2 = (uint)((byte)(uVar3 >> 0x20) & 1) << 0x1f | (uint)uVar3 >> 1;
        uVar3 = CONCAT44(uVar1,uVar2);
        iVar5 = iVar8 * iVar5 + iVar5;
        iVar8 = iVar8 * iVar8;
      } while ((uVar2 | uVar1) != 0);
      iVar5 = 1;
      iVar6 = 0x269ec3;
      defaultxClose = (void *)(iVar7 * (int)defaultxClose + iVar9);
      iVar8 = 0;
      iVar9 = 0x343fd;
      uVar3 = iOfst;
      do {
        if ((uVar3 & 1) != 0) {
          iVar8 = iVar5 * iVar6 + iVar8;
          iVar5 = iVar5 * iVar9;
        }
        uVar1 = (uint)(uVar3 >> 0x21);
        uVar2 = (uint)((byte)(uVar3 >> 0x20) & 1) << 0x1f | (uint)uVar3 >> 1;
        uVar3 = CONCAT44(uVar1,uVar2);
        iVar6 = iVar9 * iVar6 + iVar6;
        iVar9 = iVar9 * iVar9;
      } while ((uVar2 | uVar1) != 0);
      defaultxRead = (void *)(iVar5 * (int)defaultMethods->xRead + iVar8);
      defaultxWrite = defaultMethods->xWrite;
      iVar5 = 1;
      iVar8 = 0;
      iVar9 = 0x269ec3;
      iVar7 = 0x343fd;
      do {
        if ((iOfst & 1U) != 0) {
          iVar8 = iVar5 * iVar9 + iVar8;
          iVar5 = iVar5 * iVar7;
        }
        uVar1 = (uint)((ulonglong)iOfst >> 0x21);
        uVar2 = (uint)((byte)((ulonglong)iOfst >> 0x20) & 1) << 0x1f | (uint)iOfst >> 1;
        iOfst = CONCAT44(uVar1,uVar2);
        iVar9 = iVar7 * iVar9 + iVar9;
        iVar7 = iVar7 * iVar7;
      } while ((uVar2 | uVar1) != 0);
    }
    if (0 < iAmt) {
      iVar8 = iVar5 * (int)defaultxWrite + iVar8;
      do {
        uVar1 = (uint)defaultxClose >> 0x18;
        defaultxClose = (void *)((int)defaultxClose * 0x343fd + 0x269ec3);
        iAmt = iAmt + -1;
        *dst = *dst ^ (byte)((uint)defaultxRead >> 0x18) ^ (byte)uVar1 ^ (byte)((uint)iVar8 >> 0x18)
        ;
        iVar8 = iVar8 * 0x343fd + 0x269ec3;
        defaultxRead = (void *)((int)defaultxRead * 0x343fd + 0x269ec3);
        dst = dst + 1;
      } while (iAmt != 0);
    }
  }
  return iVar4;
}
```

this is probably the bulk of what we need to decipher, but let's take a
look at the other `sqlite3_vfs` methods

xDelete is a passthrough

```c
void xDelete(sqlite3_vfs *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x00010728. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)param_1->pAppData->xDelete)();
  return;
}
```

xAccess splits zName on space and only passes the text after the space
through

```c
undefined4 xAccess(sqlite3_vfs *vfs,char *zName,int flags,int *pResOut)

{
  char *pSpace;
  undefined4 res;
  
  pSpace = strchr(zName,0x20);
  if (pSpace != (char *)0x0) {
                    /* WARNING: Could not recover jumptable at 0x00010770. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    res = (*(code *)vfs->pAppData->xAccess)(vfs->pAppData,pSpace + 1,flags,pResOut);
    return res;
  }
  return 1;
}
```

xFullPathname splits zName on the space. the first part (including the
space) is copied to zOut, while the rest is passed through as the zName
parameter. nOut and zOut are adjusted so the result is written after
the space

```c

undefined4 xFullPathname(sqlite3_vfs *param_1,char *zName,int nOut,char *zOut)

{
  char *pSpace;
  undefined4 uVar1;
  char *sizeUntilSpace;
  
  pSpace = strchr(zName,0x20);
  if (pSpace != (char *)0x0) {
    sizeUntilSpace = pSpace + (1 - (int)zName);
    __aeabi_memcpy(zOut,zName,sizeUntilSpace);
                    /* WARNING: Could not recover jumptable at 0x000107dc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*(code *)param_1->pAppData->xFullPathname)
                      (param_1->pAppData,pSpace + 1,nOut - (int)sizeUntilSpace,
                       zOut + (int)sizeUntilSpace);
    return uVar1;
  }
  return 1;
}
```

xDlOpen is a passthrough. same goes for xDlError, xDlSym, xDlClose,
xRandomness, xSleep, xCurrentTime, xGetLastError, xCurrentTime

```c
void xDlOpen(sqlite3_vfs *vfs)

{
                    /* WARNING: Could not recover jumptable at 0x000107f0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)vfs->pAppData->xDlOpen)();
  return;
}
```

let's also look at the other `sqlite3_file` methods

xClose, xWrite, xTruncate, xSync, xFileSize, xLock, xUnlock,
xCheckReservedLock, xFileControl, xSectorSize, xDeviceCharacteristics,
xShmMap, xShmLock, xShmBarrier, xShmUnmap, xFetch, xUnfetch, are all
passthrough so yeah, all we need to do is figure out how xRead works

to be continued...?
