#!/usr/bin/perl

## zhunter v(whatever it says below!)
## cummingsj@gmail.com

# Copyright (C) 2010 JJ Cummings

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use warnings;
use strict;
use Socket;
use LWP::Simple;
use Getopt::Long;

# Get input methods
my %plugins = ();
my %settings = ();
my %primarydata = ();
my %zhash = ();
my $input_plugin;
RegisterPlugins();

Runtime_Options(\%settings,\%primarydata);

my $version = "v0.5";

my $zurl = get("http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist");
my $zip = get ("http://www.abuse.ch/zeustracker/blocklist.php?download=ipblocklist");

# The idea is simple, you will store the data (to be tested) in the 
# %primarydata hash, format as listed in the examples in InputPlugins
# I designed this to be modular so that you can create
# different input plugins based on your data source, the only requirements
# are that you have a date, source and dest address.. the rest is pulled 
# from the intertubes for your viewing pleasure!

#
# populate our hashes with the respective values.
#
sub build_hash {
	my ($href,$vals)=@_;
	my @data = split(/\n/,$vals);
	foreach (@data) {
		next if ($_ eq "" || $_ =~ /^#/);
		my $dest=$_;
		$dest=ip_todec($dest) if $dest =~/\d+\.\d+\.\d+\.\d+/;
		$$href{$dest}=1;
	}
	undef @data;
}

#
# Here we compare to the hash values that we just downloaded a bit ago
#
sub find_zeus {
	my ($href,$href2)=@_;
	my $i = 0;
	foreach (sort keys %$href) {
		my $dst = $$href{$_}{'dest'};
		next unless defined $$href2{$dst};
		$i++;
		print "\nPotentially Affected Systems:\n" if $i == 1;
		$dst = inet_ntoa(pack('N', $dst)) if $dst =~ /\d+/;
		print "\t".inet_ntoa(pack('N',$$href{$_}{'source'}))." communicated with Zeus C&C $dst\n";
	}
	print "\nFound $i instance(s) of potential Zeus C&C communication!\n\n";
}

#
# Trim whitespace from ^ and $ of string
#
sub trim {
	my ($trimmer)=@_;
	if ($trimmer){
		$trimmer=~s/^\s*//;
		$trimmer=~s/\s*$//;
		return $trimmer;
	}
}

#
# Convert IP to decimal value
#
sub ip_todec {
        my $ip_address = shift;
        my @octets = split(/\./, $ip_address);
        my $DEC = ($octets[0]*1<<24)+($octets[1]*1<<16)+($octets[2]*1<<8)+($octets[3]);
        return $DEC;
}

#
# Register input plugins
#
sub RegisterPlugins{
    my @plugins = glob("InputPlugins/*.pm");
    die "No input plugins found in InputPlugins directory\n" if !@plugins;

    for my $module (@plugins){
        my ($plugin) = ($module =~ m/InputPlugins\/(.*)\.pm$/);
        my $info = eval "require InputPlugins::$plugin; return InputPlugins::$plugin"."::register();";

        if($info){
			$plugins{$plugin} = $info;
            print "$plugin $info\n";
        }else{
            warn "Error loading plugin '$plugin': $@\n";
        }
    }
}

#
# Read Runtime Options
#
sub Runtime_Options {
	my ($href,$href2)=@_;
	my $err;
	GetOptions ( "r=s" => \$$href{'file'},
				 "i=s" => \$$href{'input'},
				 "v!" => \$$href{'verbose'},
                 "help|?" => sub { help() },
               );
    $err = "No Input Method Specified!\n" unless defined $$href{'input'};
    $err .= "No Input File Specified!\n" unless defined $$href{'file'};
	help($err) if $err;	
	
	# input plugin validate
	if(!exists $plugins{$$href{'input'}}){
		help ("Unknown input plugin '$settings{'input'}' selected.\n");
	}
	
	$input_plugin = $plugins{$$href{'input'}};
	print "INPL $input_plugin\n";
	
	&{$input_plugin->{init}}($href2,$$href{'file'});
}

sub help {
	my $err = shift;
	warn "-=ERROR=-\n$err\n" if $err;
print<<__EOT;
Usage: $0 -l -i <input method> -r <file to read> -help -?
	-l List available Input Plugins
	-i Input Format
	-r Input File
	-help|? display this help
	
__EOT
	exit (1) if $err;
	exit (0);	
}

print<<__EOT;

                   ,/
                 ,'/  
               ,' /   
             ,'  /_____,
           .'____    ,'    
                /  ,'  Zeus Hunter $version
               / ,'    Copyright (C) 2010 JJ Cummings
              /,'      <cummingsj\@gmail.com>
             /'
             
Using $settings{'input'} file: $settings{'file'}
             
__EOT

build_hash(\%zhash,$zip);
build_hash(\%zhash,$zurl);
find_zeus(\%primarydata,\%zhash);

__END__
