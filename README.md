**Fortify FPR file extractor**
### by [pt4tech](https://github.com/tarrinho)
I've started using Fortify to analyse the code of our applications. Like every Software Developement Life Cycle (SDLC) we needed to get the result during the pipeline, but the image that we are using doesn't have the FPRUtility.

```plaintext
 stages:
   - fortify

 fortify-sast-scancentral:
   stage: fortify
   image:
     name: fortifydocker/fortify-ci-tools:latest
```

For this reason I decided to create this bash script to unzip the fpr file and analyse its results

```plaintext
$ bash extract.bash -f scan.fpr
```

I saw in my investigations this logic and decided to use it in my code. If you have a different opinion, just contact me.

```plaintext

   if ( impact >= 2.5 && probability >= 2.5 )
   then
     Critical
   elseif ( impact >= 2.5" && probability <= 2.5 )
   then
     High
   elseif ( impact <= 2.5 && probability >= 2.5 )
   then
     Medium
   else
     Low
```

**Requirements**
 - unzip
 - bc 
 - xmllint

To install just do :
> apt get install unzip xmllint bc -y

### Changes by Shodan
The script will no longer display detailed information on screen. It will only show the total number of vulnerabilities present. If you want the comprehensive explanation now, use the following command:
```plaintext
$ bash extract.bash -f scan.fpr -e
```

You can also, instead, obtain vulnerabilities by classification `(Critical|High|Medium|Low)`:
```plaintext
$ bash extract.bash -f scan.fpr -c Critical
$ bash extract.bash -f scan.fpr -c High
```

Disclaimer: This script was made by [pt4tech](https://github.com/tarrinho) for his own purposes, and I've adapted it to mine. There is no warranty associated to this script. If you want it to work in different ways, change them yourself.
