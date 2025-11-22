###################################################################
#  This script is find if the "lost" packet, its SEQ Number
#  when the "lost" happens. this assume there's no jumbo frame
#  occurrence 1, NOT seen ---> original packet did not arrive, it's a retransmit
#  occurrence 1, seen   ---> original packet arrive, could be due to delay ack, not retransmit
#  occurence 2 or more, seen ---> original packet seen/arrive, and retransmit 
#  
#  Author: Ken Mei
############################################################################


#####@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# modified this to reflect tshark.exe installation location in your system #
#####@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

$tshark = "C:\Program Files\Wireshark\tshark.exe"

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

    $lostPacket_dupAcks =@()

    foreach ($line in $input_array) {
        
        $part0 = $Null
        $part1 = $Null

        $parts = $line -split "\t"

        $part0 = $parts[0]
        $part1 = $parts[1]

        $lost_packet = @{}
        $lost_packet.part0 = $part0
        $lost_packet.part1 = $part1

        $lostPacket_dupAcks += $lost_packet
    }

    return $lostPacket_dupAcks

}
####################################


$tracefile = read-input-trace

##########Filter to find the first dupAck of "lost" packet#############
$filter = "tcp.analysis.duplicate_ack_num == 1"

####Obtain the missing packet SEQ number and Time since the first packet of the capture####
$packet_dupAcks = & $tshark -r $tracefile -Y $filter -E "header=no" -T "fields" -e "tcp.ack" -e "frame.time_relative" -E "separator=`t"

if ($packet_dupAcks -eq $Null) {
    
    Write-Host "Network trace is being analyzed:  " $tracefile
    write-host "----> No Packet loss   <----"
} else {

    $lostpacket_dupAcks = process_tshark_output -input_array $packet_dupAcks

    # prepare filte to find packet/packets with same SEQ number as DupACK number
    $lost_packets = $Null
    $lostpackets = $Null
    $filter_to_get_lost_packets = $Null

    $count = 0

    foreach ($lostpacket_seq in $lostpacket_dupAcks) {

        if ($count -eq 0) {

            $filter_to_get_lost_packets = "tcp.seq == $($lostpacket_seq.part0)"
        } else {

            $filter_to_get_lost_packets += " || tcp.seq == $($lostpacket_seq.part0)"
        }

        $count ++

        # to avoid filter getting too large, once it hit 1000 count, procese the packets list, then reset filter and  count and continue 
        # if not, then process the  packet list outside of the for loop
        if ($count -eq 1000){

            $lost_packets += &$tshark -r $tracefile -Y $filter_to_get_lost_packets -E "header=no" -T "fields" -e "tcp.seq" -e "tcp.analysis.retransmission" -E "separator=`t"
            $filter_to_get_lost_packets = $Null
            $count = 0

        }
    }

    $lost_packets += &$tshark -r $tracefile -Y $filter_to_get_lost_packets -E "header=no" -T "fields" -e "tcp.seq" -e "tcp.analysis.retransmission" -E "separator=`t"

    $lostpackets = process_tshark_output -input_array $lost_packets

    $lost_packets_seq_occurrence = @()

    foreach ($seq in $lostpacket_dupAcks) {

        $lost_packet = @{}

        $lost_packet.seq = $seq.part0
        $lost_packet.occur_time = $seq.part1
        $lost_packet.occurrence = ($lostpackets.part0 | Where-Object { $_ -eq $($seq.part0)}).count

        $index = [array]::IndexOf($lostpackets.part0, $seq.part0)

        if ($lostpackets.part1[$index] -eq 1) {
            
            $lost_packet.state = "NOT Seen"
        } else {

            $lost_packet.state = "Seen"
        }

        $lost_packets_seq_occurrence += $lost_packet
    }

    ########Output the result on Screen##########
    Write-Host "Network trace is being Analyzed:  " $tracefile
    Write-Host "Total lost packets:  "  $packet_dupAcks.count
   

    $output = for ($i = 0; $i -lt $lost_packets_seq_occurrence.Count) {
         [Pscustomobject] @{
          occur_time = $lost_packets_seq_occurrence[$i].occur_time
          seqnum = $lost_packets_seq_occurrence[$i].seq
          occurrence = $lost_packets_seq_occurrence[$i].occurrence
          original_packet = $lost_packets_seq_occurrence[$i].state
          }
          $i++
    }
    $output
}

