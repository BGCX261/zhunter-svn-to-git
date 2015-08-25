package InputPlugins::3d_csv;

# This is a sample input plugin, the idea is simple, build plugins for what 
# you need and use them, righ!

use strict;
use warnings;

my $info = {
    input => \&input,
    description => "Reads SourceFire 3D CSV IPS Event Report, based on Table View",
};

sub register{
    return $info;
}

sub input {
	my ($href,$input)=@_;
	my $data;
	open (READ,"<$input") || die "Unable to read $input - $!\n";
	while (<READ>) {
		$data=$_;
		chomp($data);
		my ($event,$date,$impact,$engine,$proto,$source,$dest,$sport,$dport,
			$msg) = split(/,/,$data);
		$dest=ip_todec($dest) if $dest=~/\d+\.\d+\.\d+\.\d+/;
		$date="$date ".$event;
		$$href{$date}{'source'}=ip_todec($source);
		$$href{$date}{'dest'}=$dest;
	}
	close (READ);
}

__END__
