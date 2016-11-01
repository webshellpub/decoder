package decoder

import (
	"io"
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"bytes"
	"log"
)

/**********************************************************************/
/* scrdec.c - Decoder for Microsoft Script Encoder                    */
/* Version 1.8                                                        */
/*                                                                    */
/* COPYRIGHT:                                                         */
/* (c)2000-2005 MrBrownstone, mrbrownstone@ virtualconspiracy.com     */
/* v1.8 Now correctly decodes characters 0x00-0x1F, thanks to 'Zed'   */
/* v1.7 Bypassed new HTMLGuardian protection and added -dumb switch   */
/*       to disable this                                              */
/* v1.6 Added HTML Decode option (-htmldec)                           */
/* v1.5 Bypassed a cleaver trick defeating this tool                  */
/* v1.4 Some changes by Joe Steele to correct minor stuff             */
/*                                                                    */
/* DISCLAIMER:                                                        */
/* This program is for demonstrative and educational purposes only.   */
/* Use of this program is at your own risk. The author cannot be held */
/* responsible if any laws are broken by use of this program.         */
/*                                                                    */
/* If you use or distribute this code, this message should be held    */
/* intact. Also, any program based upon this code should display the  */
/* copyright message and the disclaimer.                              */
/**********************************************************************/

const (
	LEN_OUTBUF = 64
	LEN_INBUF = 1024
		
	STATE_INIT_COPY		STATE_DASP=100
	STATE_COPY_INPUT	STATE_DASP=101
	STATE_SKIP_ML		STATE_DASP=102
	STATE_CHECKSUM		STATE_DASP=103
	STATE_READLEN		STATE_DASP=104
	STATE_DECODE		STATE_DASP=105
	STATE_UNESCAPE		STATE_DASP=106
	STATE_FLUSHING		STATE_DASP=107
	STATE_DBCS			STATE_DASP=108
	STATE_INIT_READLEN	STATE_DASP=109
	STATE_URLENCODE_1	STATE_DASP=110
	STATE_URLENCODE_2	STATE_DASP=111
	STATE_WAIT_FOR_CLOSE STATE_DASP= 112
	STATE_WAIT_FOR_OPEN STATE_DASP=113
	STATE_HTMLENCODE	STATE_DASP=114
)
type STATE_DASP int

var rawData [292]byte
var pick_encoding [64]byte

var transformed [3][127]byte
var digits [0x7a]int

var urlencoded = 0
var htmlencoded = 0
var verbose = 0
var smart = 1

func unescape(c byte) byte{
	escapes := "#&!*$"
	escaped := "\r\n<>@"

	if (c > 127){
		return byte(c)
	}
	for i:=0;i<len(escapes);i++{
		if (escapes[i] == c){
			return escaped[i];			
		}
	}	
	return '?'
}

func init() {	
	//init trans
	for i:=0; i<32;i++{
		for j:=0; j<3; j++{ 
			transformed[j][i] = byte(i)
		}
	}

	for i:=31; i<=127; i++{
		for j:=0; j<3; j++ {
		
			if i==31{
				transformed[j][rawData[(i-31)*3 + j]]  = 9
			} else {
				transformed[j][rawData[(i-31)*3 + j]] = i
			}						
		}
	}

	//init digits
	for i:=0; i<26; i++	{
		digits['A'+i] = i;
		digits['a'+i] = i+26;
	}
	for  i:=0; i<10; i++	{
		digits['0'+i] = i+52;
	}
	digits[0x2b] = 62
	digits[0x2f] = 63
	
	rawData = [...]byte {
        0x64,0x37,0x69, 0x50,0x7E,0x2C, 0x22,0x5A,0x65, 0x4A,0x45,0x72, 
        0x61,0x3A,0x5B, 0x5E,0x79,0x66, 0x5D,0x59,0x75, 0x5B,0x27,0x4C, 
        0x42,0x76,0x45, 0x60,0x63,0x76, 0x23,0x62,0x2A, 0x65,0x4D,0x43, 
        0x5F,0x51,0x33, 0x7E,0x53,0x42, 0x4F,0x52,0x20, 0x52,0x20,0x63, 
        0x7A,0x26,0x4A, 0x21,0x54,0x5A, 0x46,0x71,0x38, 0x20,0x2B,0x79, 
        0x26,0x66,0x32, 0x63,0x2A,0x57, 0x2A,0x58,0x6C, 0x76,0x7F,0x2B, 
        0x47,0x7B,0x46, 0x25,0x30,0x52, 0x2C,0x31,0x4F, 0x29,0x6C,0x3D, 
        0x69,0x49,0x70, 0x3F,0x3F,0x3F, 0x27,0x78,0x7B, 0x3F,0x3F,0x3F, 
        0x67,0x5F,0x51, 0x3F,0x3F,0x3F, 0x62,0x29,0x7A, 0x41,0x24,0x7E, 
        0x5A,0x2F,0x3B, 0x66,0x39,0x47, 0x32,0x33,0x41, 0x73,0x6F,0x77, 
        0x4D,0x21,0x56, 0x43,0x75,0x5F, 0x71,0x28,0x26, 0x39,0x42,0x78, 
        0x7C,0x46,0x6E, 0x53,0x4A,0x64, 0x48,0x5C,0x74, 0x31,0x48,0x67, 
        0x72,0x36,0x7D, 0x6E,0x4B,0x68, 0x70,0x7D,0x35, 0x49,0x5D,0x22, 
        0x3F,0x6A,0x55, 0x4B,0x50,0x3A, 0x6A,0x69,0x60, 0x2E,0x23,0x6A, 
        0x7F,0x09,0x71, 0x28,0x70,0x6F, 0x35,0x65,0x49, 0x7D,0x74,0x5C, 
        0x24,0x2C,0x5D, 0x2D,0x77,0x27, 0x54,0x44,0x59, 0x37,0x3F,0x25, 
        0x7B,0x6D,0x7C, 0x3D,0x7C,0x23, 0x6C,0x43,0x6D, 0x34,0x38,0x28, 
        0x6D,0x5E,0x31, 0x4E,0x5B,0x39, 0x2B,0x6E,0x7F, 0x30,0x57,0x36, 
        0x6F,0x4C,0x54, 0x74,0x34,0x34, 0x6B,0x72,0x62, 0x4C,0x25,0x4E, 
        0x33,0x56,0x30, 0x56,0x73,0x5E, 0x3A,0x68,0x73, 0x78,0x55,0x09, 
        0x57,0x47,0x4B, 0x77,0x32,0x61, 0x3B,0x35,0x24, 0x44,0x2E,0x4D, 
        0x2F,0x64,0x6B, 0x59,0x4F,0x44, 0x45,0x3B,0x21, 0x5C,0x2D,0x37, 
        0x68,0x41,0x53, 0x36,0x61,0x58, 0x58,0x7A,0x48, 0x79,0x22,0x2E, 
        0x09,0x60,0x50, 0x75,0x6B,0x2D, 0x38,0x4E,0x29, 0x55,0x3D,0x3F,
		0x51,0x67,0x2f,
	}	
	pick_encoding = [64]byte{
	1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0, 
	1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2, 
	1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2, 
	1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2,
	}
	
	entities = []entitymap {
	{"excl",33},{"quot",34},{"num",35},{"dollar",36},{"percent",37},
	{"amp",38},{"apos",39},{"lpar",40},{"rpar",41},{"ast",42},
	{"plus",43},{"comma",44},{"period",46},{"colon",58},{"semi",59},
	{"lt",60},{"equals",61},{"gt",62},{"quest",63},{"commat",64},
	{"lsqb",91},{"rsqb",93},{"lowbar",95},{"lcub",123},{"verbar",124},
	{"rcub",125},{"tilde",126}, {NULL, 0},
	}
}

func decodeBase64(p []byte) uint32 {
	var val uint32

	val +=  (digits[p[0]] << 2)
	val +=  (digits[p[1]] >> 4)
	val +=  (digits[p[1]] & 0xf) << 12
	val += ((digits[p[2]] >> 2) << 8)
	val += ((digits[p[2]] & 0x3) << 22)
	val +=  (digits[p[3]] << 16)
	val += ((digits[p[4]] << 2) << 24)
	val += ((digits[p[5]] >> 4) << 24)
	/* 543210 543210 543210 543210 543210 543210

	   765432 
	          10
	                 ba98
	            fedc
	                     76
	                        543210
                                   fedcba 98----
       |- LSB -||-     -||-     -| |- MSB -|
	*/
	return val;
}

/*
 Char. number range  |        UTF-8 octet sequence
      (hexadecimal)    |              (binary)
   --------------------+---------------------------------------------
   0000 0000-0000 007F | 0xxxxxxx
   0000 0080-0000 07FF | 110xxxxx 10xxxxxx
   0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
   0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
*/

func isLeadByte(cp uint, ucByte byte) bool{
	/* Code page 932 - Japanese Shift-JIS       - 0x81-0x9f 
	                                              0xe0-0xfc 
                 936 - Simplified Chinese GBK   - 0xa1-0xfe
	             949 - Korean Wansung           - 0x81-0xfe
				 950 - Traditional Chinese Big5 - 0x81-0xfe 
	            1361 - Korean Johab             - 0x84-0xd3 
												  0xd9-0xde
												  0xe0-0xf9 */
	switch (cp)	{
		case 932:
			if (ucByte > 0x80) && (ucByte < 0xa0)	{
				return true
				}
			if (ucByte > 0xdf) && (ucByte < 0xfd)	{
			return true
			}
			
		case 936:
			if (ucByte > 0xa0) && (ucByte < 0xff) {
				return true
				}
				
		case 949,950:
			if (ucByte > 0x80) && (ucByte < 0xff) {
				return true
			}
		case 1361:
			if (ucByte > 0x83) && (ucByte < 0xd4) {
			return true
			}
			if (ucByte > 0xd8) && (ucByte < 0xdf){
				return true
			} 
			if (ucByte > 0xdf) && (ucByte < 0xfa) {
				return true
			}
		default:
			return false;
	}
	return false
}

type entitymap struct{
	entity string
	mappedchar int
}

var entities []entitymap

func decodeMnemonic(mnemonic []byte) byte {
	i := 0
	for (entities[i].entity != NULL)	{
		if (strcmp(entities[i].entity, string(mnemonic))==0){
			return byte(entities[i].mappedchar)
		}
		i++
	}
	log.Println("Warning: did not recognize HTML entity '%s'\n", mnemonic);
	return '?'
}


func decoderScriptMemToMem(inscript[]byte, deHtml, deUrl bool) ([]byte,error) {
	cp := 936
	retcur := 0
	var inbuf [LEN_INBUF+1]byte
	var outbuf [LEN_OUTBUF+1]byte
	var c, c1, c2 byte
	var lenbuf [7]byte
	var csbuf [7]byte
	var htmldec [8]byte
	
	marker := "#@~^"
	var ustate, nextstate, state int
	var i, j, k, m, ml, hd  int
	var utf8 int
	var csum uint
	var decodeLen uint
	
	bufin := bufio.NewReader(f)
		
	i = 0
	j = 0
	wbytebuf := bytes.NewBuffer(nil)
	state := STATE_INIT_COPY
	
	for inidx:=0; inidx<len(inscript)&&state!=0; inidx++ {					
		switch (state)		{
			case STATE_INIT_COPY: 
				ml = len(marker)
				m = 0;
				state = STATE_COPY_INPUT

			/* after decoding a block, we have to wait for the current 
			   script block to be closed (>) */		
			case STATE_WAIT_FOR_CLOSE:
				if (inbuf[i] == '>')
					state = STATE_WAIT_FOR_OPEN;
				outbuf[j] = inbuf[i]
				j++
				i++

			/* and a new block to be opened again (<) */
			case STATE_WAIT_FOR_OPEN:
				if (inbuf[i] == '<') {
					state = STATE_INIT_COPY
				}
				outbuf[j] = inbuf[i]
				j++
				i++

			case STATE_COPY_INPUT:
				if (inbuf[i] == marker[m]){
					i++
					m++
				}	else {
					if (m) {
						k = 0
						state = STATE_FLUSHING
					}	else {
						wbytebuf.Write(inbuf[i++])
					}
				}
				if (m == ml){
					state = STATE_INIT_READLEN;
				}
				
			case STATE_FLUSHING:
				outbuf[j] = marker[k]
				j++
				k++
				m--
				if (m==0){
					state = STATE_COPY_INPUT;
				}
				
			case STATE_SKIP_ML: 
				i++
				if (!(--ml)){
					state = nextstate;
				}

			case STATE_INIT_READLEN: 
				ml = 6
				state = STATE_READLEN

			case STATE_READLEN: 
				lenbuf[6-ml] = inbuf[i]
				i++
				if (!(--ml))				{
					decodeLen = decodeBase64(lenbuf);
					if (verbose)
						log.Printf("Msg: Found encoded block containing %d characters.\n", decodeLen);
					m = 0
					ml = 2
					state = STATE_SKIP_ML;
					nextstate = STATE_DECODE;
				}

			case STATE_DECODE: 
				if (!decodeLen) {
					ml = 6
					state = STATE_CHECKSUM
					break
				}
				if (inbuf[i] == '@') {
					state = STATE_UNESCAPE
					}else{
					if ((inbuf[i] & 0x80) == 0)					{
						c = transformed[pick_encoding[m%64]][inbuf[i]]
						wbytebuf.Write(c)
						csum += c
						m++
					}	else 	{
						if (!cp && (inbuf[i] & 0xc0)== 0x80) 
						{
							// utf-8 but not a start byte
							decodeLen++
							utf8=1
						}
						outbuf[j++] = inbuf[i];
						if ((cp) && (isLeadByte (cp,inbuf[i])))
							state = STATE_DBCS;
					}
				}
				i++
				decodeLen--

			case STATE_DBCS:
				wbytebuf.Write(inbuf[i])
				i++
				state = STATE_DECODE
				
			case STATE_UNESCAPE: 
				c = unescape(inbuf[i])
				wbytebuf.Write(c)
				i++				
				csum += c
				decodeLen--
				m++
				state = STATE_DECODE

			case STATE_CHECKSUM: 
				csbuf[6-ml] = inbuf[i]
				i++
				if (!(--ml))	{
					csum -= decodeBase64(csbuf)
					if (csum)
					{
						log.Printf("Error: Incorrect checksum! (%lu)\n", csum)
						if (cp){
							log.Printf("Tip: Maybe try another codepage.\n")
						}
						else
						{
							if (utf8>0){
								log.Printf("Tip: The file seems to contain special characters, try the -cp option.\n");						
							}	else{
								log.Printf("Tip: the file may be corrupted.\n")
							}
						}
						csum=0
					}
					else {
						if (verbose)
							log.Printf( "Msg: Checksum OK\n");
					}
					m = 0
					ml = 6
					state = STATE_SKIP_ML
					if (smart){
	 					nextstate = STATE_WAIT_FOR_CLOSE
					}	else {
						nextstate = STATE_INIT_COPY
					}
				}

			default:
				log.Println("Internal Error: Invalid state: ", state);
		}
	}
	
	return wbytebuf.Bytes(),nil
}

