# DefenderCheck
Quick tool to help make evasion work a little bit easier.

Takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on, and then prints those offending bytes to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.

Simple tweak adjustment to show why the file triggered - somethimes I have found if the trigger bytes were the very last bytes in file, even though it triggered AV, DefenderCheck would say it was clean.

Testing with a simple eicar.com file

![image](https://user-images.githubusercontent.com/21687763/147253420-6d405db2-8bcd-4c45-a1cf-d1fe033b8b0e.png)


This fork of DefenderCheck (just with some extra output)

![image](https://user-images.githubusercontent.com/21687763/147253442-5471f86a-630a-4731-99cd-ae9810965ed9.png)

If this happens, chances are it's the last couple of bytes in the file that are triggering Defender. At least you know where to look. 

Reference : https://github.com/matterpreter/DefenderCheck/issues/21
