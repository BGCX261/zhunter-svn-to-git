package InputPlugins::squid_unified;

use strict;
use warnings;

my $info = {
    input => \&input,
    description => "Reads squid native format logs",
};

sub register{
    return $info;
}

# (emulate_httpd_log_off)
sub init {
	my ($href,$input)=@_;
	my $data;
	open (READ,"<$input") || die "Unable to read $input -$!\n";
	while (<READ>) {
		$data=$_;
		chomp($data);
		my ($timestamp,$elapsed,$source,$result,$size,$method,$ident,$dash,
			$dest,$content_type)=split(/\s+/,$data);
		$dest=~s/\w*\/?//;
		$timestamp=gmtime($timestamp);
		$dest=ip_todec($dest) if $dest=~/\d+\.\d+\.\d+\.\d+/;
		$timestamp="$timestamp ".int(rand(1000));
		$$href{$timestamp}{'source'}=ip_todec($source);
		$$href{$timestamp}{'dest'}=$dest;
	}
	close (READ);
}
