package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
	"os/exec"
	"strings"
	"io/ioutil"
    "encoding/hex"
    "strconv"
    "log"
    "os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Client struct {
	Name         string
	SerialNumber string
}
type Software struct {
	DateInstall string
}

type SoftwareName = string

type SoftwareList map[SoftwareName]Software
type WebsiteList map[string]string
type ApplicationRunning struct {
	Name            string
	Description     string
	MainWindowTitle string
}

type ApplicationRunningList map[string]ApplicationRunning
func (client *Client) getApplicationRunning() ApplicationRunningList{
    applicationRunningList:=make(ApplicationRunningList)
    
	apps, err:=exec.Command("sudo","wmctrl", "-l").Output()
    if err != nil {
		log.Fatal(err)
	}
    cmd:="sudo wmctrl -l -x | awk '{print $3}'"
    class, err:=exec.Command("bash", "-c",cmd).Output()
    if err != nil {
		log.Fatal(err)
	}
    count := 0
    i := 0
    lines := strings.Split(string(apps), "\n")
    classArr:=strings.Split(string(class), "\n")
    var title string
    for index, _ := range lines {
        if lines[index]==""{
            continue
        }
        
		for _, w := range strings.Fields(lines[index]) {
            
            if count == 3 {
                break
            }
            count++
            i += len(w) + 1
        }
        class:=strings.Split(classArr[index],".")

        title=lines[index][i:]
        applicationRunningList[title]=ApplicationRunning{class[len(class)-1],"",title}

	}
    return applicationRunningList
}
func (client *Client) getSerialNumber() (name string) {
	cmd := "dmidecode -t 1 | grep -i serial"
	serial, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "Unknown"
	}
	return string(serial)[16 : len(serial)-1]
}
func (client *Client) getMacAddr() (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var as string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" && (ifa.Name[0] == 'e' || ifa.Name[0] == 'w') && ifa.Flags.String()[0] == 'u' {
			as = ifa.Name + " " + a
		}

	}
	return as, nil
}

func (client *Client) getSoftwareInstalled() SoftwareList {
	installedPackages := make(SoftwareList)
	cmd := "zgrep 'install ' /var/log/dpkg.log* | sort | cut -f1,4 -d' '"
	dpkg, err := exec.Command("bash", "-c", cmd).Output()

	if err != nil {
		fmt.Println("Error:", err)
	}

	lines := strings.Split(string(dpkg), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		arr := strings.Split(string(line), " ")

		packageName := strings.Split(string(arr[1]), ":")[0]
		installDate := strings.Split(string(arr[0]), ":")[1]

		if _, ok := installedPackages[packageName]; !ok {
			installedPackages[packageName] = Software{installDate}
		}
	}
	return installedPackages
}
func monitorApplication() {
	go func() {
		oldInstalledPackages := client.getSoftwareInstalled()
		for packageName, s := range client.getSoftwareInstalled() {
			if packageName == "" {
				continue
			}
			mac, _ := client.getMacAddr()
			software.With(prometheus.Labels{
				"ClientName":     "tm",
				"ClientAddress":  mac,
				"SoftwareName":   packageName,
				"DeviceSerialNo": client.getSerialNumber(),
				"DateInstalled":  s.DateInstall,
			}).Set(1)
		}
		for {
			newInstalledPackages := client.getSoftwareInstalled()
			for packageName, s := range oldInstalledPackages {
				if _, ok := newInstalledPackages[packageName]; !ok {
					fmt.Println("software uninstalled", packageName)
					mac, _ := client.getMacAddr()
					software.Delete(prometheus.Labels{
						"ClientName":     "tm",
						"ClientAddress":  mac,
						"SoftwareName":   packageName,
						"DeviceSerialNo": client.getSerialNumber(),
						"DateInstalled":  s.DateInstall,
					})
				}
			}

			for packageName, s := range newInstalledPackages {
				if _, ok := oldInstalledPackages[packageName]; !ok {
					fmt.Println("new software installed", packageName)
					mac, _ := client.getMacAddr()
					software.With(prometheus.Labels{
						"ClientName":     "tm",
						"ClientAddress":  mac,
						"SoftwareName":   packageName,
						"DeviceSerialNo": client.getSerialNumber(),
						"DateInstalled":  s.DateInstall,
					}).Set(1)
				}
			}
			oldInstalledPackages = newInstalledPackages
			time.Sleep(time.Second * 10)
		}
	}()
    go func() {
		oldInstalledPackages := client.getApplicationRunning()
		for packageName, s := range client.getApplicationRunning() {
			if packageName == "" {
				continue
			}
			mac, _ := client.getMacAddr()
			softwareRunning.With(prometheus.Labels{
				"ClientName":     "tm",
				"ClientAddress":  mac,
				"SoftwareName":   packageName,
				"DeviceSerialNo": client.getSerialNumber(),
				"Name":  s.Name,
			}).Set(1)
		}
		for {
			newInstalledPackages := client.getApplicationRunning()
			for packageName, s := range oldInstalledPackages {
				if _, ok := newInstalledPackages[packageName]; !ok {
					
					mac, _ := client.getMacAddr()
					softwareRunning.Delete(prometheus.Labels{
						"ClientName":     "tm",
						"ClientAddress":  mac,
						"SoftwareName":   packageName,
						"DeviceSerialNo": client.getSerialNumber(),
						"Name": s.Name,
					})
				}
			}

			for packageName, s := range newInstalledPackages {
				if _, ok := oldInstalledPackages[packageName]; !ok {
					
					mac, _ := client.getMacAddr()
                    softwareRunning.With(prometheus.Labels{
                        "ClientName":     "tm",
                        "ClientAddress":  mac,
                        "SoftwareName":   packageName,
                        "DeviceSerialNo": client.getSerialNumber(),
                        "Name":  s.Name,
                    }).Set(1)
				}
			}
			oldInstalledPackages = newInstalledPackages
			time.Sleep(time.Second * 10)
		}
	}()
}

var (
	software = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ivs",
			Subsystem: "client",
			Name:      "software_installed",
			Help:      "new software installed",
		},
		[]string{
			"ClientName",
			"ClientAddress",
			"SoftwareName",
			"DeviceSerialNo",
			"DateInstalled",
		},
	)
    softwareRunning = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ivs",
			Subsystem: "client",
			Name:      "software_Running",
			Help:      "software running",
		},
		[]string{
			"ClientName",
			"ClientAddress",
			"SoftwareName",
			"DeviceSerialNo",
			"Name",
		},
	)
    website = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ivs",
			Subsystem: "client",
			Name:      "accessed_website",
			Help:      "website accessed by node",
		},
		[]string{
			"DomainName",
			"IPAddress",
		},
	)
	client *Client
)
func getLockScreenStatus() bool {
	cmd:="sudo loginctl show-user -p IdleHint"
	screen, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return false
	}
	state:=strings.Split(string(screen),"=")[1]
	if state[:len(state)-1] == "yes" {
		return true
	} else{
		return false
	}
}
func getWifiName() string {
	ifas, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
        
		if a != "" && ifa.Name[0] == 'w' && ifa.Flags.String()[0] == 'u' {
			return ifa.Name
		}
	}
	return ""
}
func getEthernetName() string {
	ifas, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" && ifa.Name[0] == 'e' && ifa.Flags.String()[0] == 'u' {
            cmd := "nmcli device status | grep -i "+ifa.Name
            e, err := exec.Command("bash", "-c", cmd).Output()
            if err != nil {
                return ifa.Name
            }
            status:=strings.Fields(string(e))[2]
            if status=="disconnected"{
                return ""
            }
			return ifa.Name
		}
	}
	return ""
}
func getVPNName() string {
	ifas, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, ifa := range ifas {
		if ifa.Name[0] == 'u' {
			return ifa.Name
		}
	}
	return ""
}
//not sure...
func getDomainAndIP(payload string) (string,[]string){
    //index of c00c
    index:=strings.Index(payload,"c00c")
    //domain name in dns answer
    domainInHex:=payload[28:index-8]
    //ip in dns answer
    
    var domainName string
    for {
        //0463686174047a616c6f026d6500 domain in hex format of chat.zalo.me
        //04 -> length of level is 4
        //63686174 -> convert to string from hex got chat   \
        //04                                                 \
        //7a616c6f -> convert to string from hex got zalo     -> chat.zalo.me
        //02                                                 /
        //6d65  -> convert to string from hex got me        /
        //00 end
        
        lengthInHex:=domainInHex[:2]//get level length of domain
        lengthInDecimal, err := strconv.ParseInt(lengthInHex, 16, 64)// convert length to decimal from hex
        if err != nil {
            fmt.Println(err)
        }
        domainNameLevel,err:=hex.DecodeString(domainInHex[2:(lengthInDecimal+1)*2])// convert to string
        if err!=nil{
            break
        }
        domainName=domainName+string(domainNameLevel)+"."//concatenate level to domain
        domainInHex=domainInHex[2+lengthInDecimal*2:]//update domain in hex format from 0463686174047a616c6f026d6500 -> 047a616c6f026d6500
        if lengthInHex=="00"{
            break
        }
    }
    IPAddress:=[]string{}
    //ipInHex got format like this example: 31 d5 4e 80 
    ipAnswer:=payload[index:]
    for{
        if ipAnswer[4:8]=="0001"{
            ipInHex:=ipAnswer[24:32]
            var IP string
            //ipInHex got format like this example: 31 d5 4e 80 
            for i :=0;i<4;i++{
                IPLevel, err := strconv.ParseInt(ipInHex[i*2:i*2+2], 16, 64)// from hex to int 31->49, d5->213, 4e->78, 80->128
                if err != nil {
                    fmt.Println(err)
                }
                IP=IP+strconv.FormatInt(IPLevel, 10)+"."//concatenate level part of ip to final ip    
            }
            
            ipAnswer=ipAnswer[32:]
            IPAddress=append(IPAddress,IP[:len(IP)-1])
            if len(ipAnswer)==0{
                break
            }
            if ipAnswer[:4]=="0000"{
                break
            }
        }else{
            AnswerLength,err:=strconv.ParseInt(ipAnswer[20:24], 16, 64)
            if err != nil {
                    fmt.Println(err)
            }
            ipAnswer=ipAnswer[20+2*AnswerLength+4:]
        }
    }
    
    return domainName[:len(domainName)-2],IPAddress
}
func storeDNSTCP(layer gopacket.Layer,file *os.File,web []string){
    tcp, ok := layer.(*layers.TCP)//check if layer is actually TCP
    if !ok {
        return 
    }         
    //if TCP packet is a DNS query

    fmt.Println("tcp",tcp.DstPort.String(),tcp.SrcPort.String())    
    fmt.Println("tcp",hex.EncodeToString(tcp.LayerPayload()))
    if (tcp.DstPort.String()=="53(domain)" || tcp.SrcPort.String()=="53(domain)") && len(tcp.LayerPayload())!=0{
        payloadString:=hex.EncodeToString(tcp.LayerPayload())
        //extract information in answer query payload so check c00c
        if strings.Index(payloadString[:],"c00c")==-1{
            return
        }
        tcpDomainName,Ip:=getDomainAndIP(payloadString[:])
        var flag bool = false
        for _,w:=range web{
            if strings.Contains(tcpDomainName,w){
                flag=true
                break
            }
        } 
        if !flag{
            return
        }
        for _,ip:=range Ip{
            _, err := file.WriteString(tcpDomainName+" "+ip+"\n")
            if err != nil {
                log.Fatalf("failed writing to file: %s", err)
            }
        }
    } 
}
func storeDNSUDP(layer gopacket.Layer,file *os.File,web []string){
    var domainName string=""
    dns, ok := layer.(*layers.DNS)//check if layer is actually DNS
    if !ok {
        return 
    }

    for _,question:=range dns.Questions {
        //type A is a DNS query for IP address
        if question.Type==1{
            //get domain name of query
            domainName=string(question.Name[:])
            var flag bool=false
            for _,w:=range web{
                if strings.Contains(domainName,w){
                    flag=true
                    return
                }
            } 
            if !flag{
                return
            }
        }  
    }
    
    //check all answer because answer may contain multiple IP address
    for _,answer:= range dns.Answers{
        //type A is a DNS query for IP address
        if answer.Type==1{
            _, err := file.WriteString(domainName+" "+answer.IP.String()+"\n")
            if err != nil {
                log.Fatalf("failed writing to file: %s", err)
            }
        }
    }
}
func readPacketIP(layer gopacket.Layer){
    ip, ok := layer.(*layers.IPv4)//check if layer is actually IPv4
    if !ok {
        return 
    }
    data, err := ioutil.ReadFile("text.txt")
    if err != nil {
        log.Panicf("failed reading data from file: %s", err)
    }
    //get all domain and ip in file and store to s
    s := string(data)
    arr:=strings.Split(s,"\n")//split line by line
    for _,line:=range arr{
        if strings.Contains(line,ip.DstIP.String()){
            domain:=strings.Split(line," ")[0]
            fmt.Println("current connect to: ",domain)
            website.With(prometheus.Labels{
                "DomainName":     domain,
                "IPAddress":  ip.DstIP.String(),
            }).Set(1)
            //this code will have one metric. Metric will be 1 if list of known website is accessed otherwise is will be 0.
            //have to know what website will be watch
        }
    }
}
func monitoringNetwork(){
    for{
        //file contain list of domain and it ip. Use this file to ensure that if system is down and restart dns will stay there. Because of dns cache
        //when system is down dns query will not be sent again.
        MonitorWebsite:=[]string{"facebook","github","tiktok","instagram","zalo","youtube"}
        file,err:=os.OpenFile("text.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
        if err != nil {
            log.Fatal(err)
        }
        defer file.Close()
        //get device name
        var device string =getVPNName()
        //flag is used to detect if user is switch network from ethernet to wifi and vice versa
        var flag int=0
        if device==""{
            device=getEthernetName()
            if device==""{
                device=getWifiName()
                if device!=""{
                    flag=2
                }
            }else{
                flag=1
            }
        }
        //InActiveHandle function in pcap is alternative. Have not researched yet
        if handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever); err != nil {
            continue
        } else {
            defer handle.Close()//move to end of function because of defer
            //capture tcp or udp
            if err := handle.SetBPFFilter("tcp or udp"); err != nil {
                panic(err)
            }
            //source of packet
            //handle.LinkType is type of link, ie: ethernet, sccp,...
            packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
            for packet := range packetSource.Packets() {
                //capture dn. Layer returns the first layer in this packet of type DNS
                dnsLayer := packet.Layer(layers.LayerTypeDNS)
                
                if dnsLayer != nil {
                    //store DNS question and answer information in format to file: domainName returnIP\n
                    storeDNSUDP(dnsLayer,file,MonitorWebsite)
                }
                // if dns query use tcp protocol
                tcpLayer:=packet.Layer(layers.LayerTypeTCP)
                if tcpLayer!=nil{
                    //store DNS question and answer information in format to file: domainName returnIP\n
                    storeDNSTCP(tcpLayer,file,MonitorWebsite)
                }
                //capture ip of packet
                ipLayer  := packet.Layer(layers.LayerTypeIPv4)
                if ipLayer!=nil{
                    continue
                    //readPacketIP(ipLayer)
                }
                //handle when user switch network from ethernet to wifi and vice versa
                if flag==2{
                    if getWifiName()==""{
                        break
                    }else if getEthernetName()!="" {
                        break
                    }else if getVPNName()!="" {
                        break
                    }
                }else if flag==1{
                    if getEthernetName()==""{
                        break
                    }else if getVPNName()!=""{
                        break
                    }
                }else {
                    if getVPNName()==""{
                        break
                    }
                }
            }
        }
    }
}
func main() {
	//monitorApplication()
    monitorApplication()
	//prometheus.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9101", nil)
}
