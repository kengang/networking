###################################################################
#  This script is to find out total the client did not send data and 
#  waiting for reciever to recover from TCP Zero Windows or 
#  Windows less than a Full Mss < 1500
#  
#  only works well on a single tcp stream trace
#  
#  Author: Ken Mei
############################################################################


#####@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# modified this to reflect tshark.exe installation location in your system #
#####@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

$tshark = "C:\Program Files\Wireshark\tshark.exe"
$capinfo = "C:\Program Files\Wireshark\capinfos.exe"

#################################
Function read-input-trace {
    # Load the required assembly
    Add-Type -AssemblyName System.Windows.Forms

    # Create an OpenFileDialog object
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop') # Default directory
    $OpenFileDialog.Filter = "pcap/pcapng |*.pcap;*.pcapng" # File filter
    $OpenFileDialog.Title = "Select a file to read"

    # Show the dialog and check if the user selected a file
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $FilePath = $OpenFileDialog.FileName
        Write-Host "You selected: $FilePath"

        return $FilePath
       
    } else {
        Write-Host "No file was selected."
    }
}
#################################

#################################
Function process_tshark_output {
    param(
        [array]$input_array
    )

    $outputs =@()

    foreach ($line in $input_array) {
        
        $part0 = $Null
        $part1 = $Null

        $parts = $line -split "\t"

        $part0 = $parts[0]
        $part1 = $parts[1]
        $part2 = $parts[2]
        $part3 = $parts[3]
        $part = @{}

        $part.part0 = $part0
        $part.part1 = $part1
        $part.part2 = $part2
        $part.part3 = $part3

        $outputs += $part
    }

    return  $outputs

}
####################################


$tracefile = read-input-trace

#check if the trace missing 3-way handshake or the tcp windows scaling factor is capture
# then determine the tshark filter
$3wayhandshake = & $tshark -r $tracefile -Y "tcp.window_size_scalefactor == -1"
if ($3wayhandshake -eq $null) {
    $filter = "(tcp.window_size <1500 and ! tcp.analysis.zero_window_probe_ack) || tcp.analysis.window_update"
} else{
$filter = "(tcp.window_size <5 and ! tcp.analysis.zero_window_probe_ack) || tcp.analysis.window_update"
}
####Obtain the missing packet SEQ number and Time since the first packet of the capture####
$tcpwindows_updates = & $tshark -r $tracefile -Y $filter -E "header=no" -T "fields" -e "frame.number" -e "frame.time_relative" -e "tcp.window_size" -e "tcp.analysis.window_update" -E "separator=`t"

$tcp_window_evts = process_tshark_output -input_array $tcpwindows_updates 


$all_tcp_window_updae_evts = @()

for ($i = 0; $i -lt $tcp_window_evts.count; $i++){

    $tcp_window_update_evt = @{}
    if ($tcp_window_evts[$i].part3 -ne 1) {
        
        for($j = $i; $j -lt ($i+5); $j++){

            if ($tcp_window_evts[$j].part3 -eq 1) {

                $tcp_window_update_evt.window_full_frame = $tcp_window_evts[$i].part0
                $tcp_window_update_evt.window_full_time = $tcp_window_evts[$i].part1
                $tcp_window_update_evt.window_update_frame = $tcp_window_evts[$j].part0
                $tcp_window_update_evt.window_update_time = $tcp_window_evts[$j].part1
                $tcp_window_update_evt.window_wasted_time = ($tcp_window_evts[$j].part1 - $tcp_window_evts[$i].part1)

                $i = $j
                break;
            }
        }

    }

    $all_tcp_window_updae_evts += $tcp_window_update_evt
}

# calc the overall time and output result
$overall_wasted_time = 0

foreach ($evt in $all_tcp_window_updae_evts) {
$evt.window_wasted_time
    $overall_wasted_time += $evt.window_wasted_time
}

& $capinfo -a -e -u -i $tracefile

Write-Host "Overall time (seconds) Reciever TCP Zero Window wasted: " $overall_wasted_time