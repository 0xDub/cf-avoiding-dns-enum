use addr::parse_domain_name;
use domain::resolv::StubResolver;
use domain::rdata::AllRecordData;
use domain::base::iana::Rtype;
use domain::base::iana::Class;
use domain::base::name::Name;
use domain::base::Question;
use std::net::Ipv6Addr;
use std::net::Ipv4Addr;
use iprange::IpRange;
use ipnet::Ipv6Net;
use ipnet::Ipv4Net;
use std::str::FromStr;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::env;

mod utils;
use utils::CL;

mod cf_json;
use cf_json::CloudFlareIPs;

use crate::utils::FileHandler;


async fn query(
    resolver: &StubResolver, 
    question: Question<Name<Vec<u8>>>, 
    tag: &str, 
    targets: &mut Vec<Name<Vec<u8>>>, 
    non_cloudflare_ips: &mut Vec<String>,
    recursively_found_domains: &mut Vec<String>,
    ipv4_range: &IpRange<Ipv4Net>, 
    ipv6_range: &IpRange<Ipv6Net>,
) {
    let answer = resolver.query(question).await;
    match answer {
        Ok(answer) => {
            let records = answer.answer().unwrap().limit_to::<AllRecordData<_, _>>();
            for record in records {
                let record = record.unwrap();

                let mut found_something: bool = false;
                let data = record.data().to_string();
                match parse_domain_name(&data) {
                    Ok(_) => {
                        let domain_name = Name::<Vec<_>>::from_str(&data).expect("Failed to parse domain name");
                        if !targets.contains(&domain_name) {
                            targets.push(domain_name);
                            recursively_found_domains.push(data.clone());
                            found_something = true;
                        }
                    },
                    Err(_) => {
                        // check if IPv4 or IPv6
                        
                        let ip = Ipv4Addr::from_str(&data);
                        if let Ok(ip) = ip {
                            match (!ipv4_range.contains(&ip), !non_cloudflare_ips.contains(&data)) {
                                (true, true) => {
                                    non_cloudflare_ips.push(data.clone()); // technically not needed since it'll only satisfy either IPv4 or IPv6 but for printing-the-result sake we'll need to clone
                                    found_something = true;
                                },
                                (false, _) => {}, // cloudfare IP
                                _ => {} // duplicate IP
                            }
                        }

                        let ip = Ipv6Addr::from_str(&data);
                        if let Ok(ip) = ip {
                            match (!ipv6_range.contains(&ip), !non_cloudflare_ips.contains(&data)) {
                                (true, true) => {
                                    non_cloudflare_ips.push(data);
                                    found_something = true;
                                },
                                (false, _) => {}, // cloudfare IP
                                _ => {} // duplicate IP
                            }
                        }
                    }
                }
                match found_something {
                    true => println!("{}{}{} {}|:|{} {}{}{}", CL::Dull.get(), tag, CL::End.get(), CL::Green.get(), CL::End.get(), CL::Dull.get(), record, CL::End.get()),
                    false => println!("{}{}{} {}|:| {}{}", CL::Dull.get(), tag, CL::End.get(), CL::Dull.get(), record, CL::End.get()),
                }
            }
        },
        Err(e) => {
            println!("{}[!]{} Error querying: {:?}", CL::DullRed.get(), CL::End.get(), e);
        }
    }
}


fn load_subdomains() -> Vec<String> {
    let mut loaded_subdomains: Vec<String> = Vec::new();
    let file = File::open("subdomains.txt").unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(line) = line {
            loaded_subdomains.push(line);
        }
    }
    loaded_subdomains
}


#[tokio::main]
async fn main() {
    println!("{}[*]{} Starting Cloudflare IP Sniffer...", CL::Pink.get(), CL::End.get());
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 2 {
        println!("{}[!]{} Usage: cargo run <domain> <use_subdomains? (y/n)>", CL::DullRed.get(), CL::End.get());
        std::process::exit(1);
    }
    let central_domain = Name::<Vec<_>>::from_str(&args[0].to_string()).expect("Failed to parse domain name");
    let use_subdomains = args.len() > 1 && args[1] == "y";

    let mut targets: Vec<Name<Vec<u8>>> = Vec::new();
    let mut subdomains: Vec<String> = Vec::new();
    if use_subdomains {
        subdomains = load_subdomains();
    }
    
    println!("{}[-]{} Central domain: {:?}", CL::Dull.get(), CL::End.get(), central_domain);
    println!("{}[-]{} Subdomains loaded: {}x", CL::Dull.get(), CL::End.get(), subdomains.len());

    targets.push(central_domain.clone());
    for subdomain in subdomains {
        let full_domain = format!("{}.{}", subdomain, central_domain);
        let target = Name::<Vec<_>>::from_str(&full_domain).expect("Failed to parse subdomain");
        targets.push(target);
    }

    // load up cloudflare IPs so we can avoid them (they mask the real IP of the servers we're looking for)
    let cf_result = reqwest::get("https://api.cloudflare.com/client/v4/ips?networks=jdcloud")
        .await.expect("Failed to send request")
        .json::<CloudFlareIPs>()
        .await;
    if let Ok(cf_result) = cf_result {
        let mut recursively_found_domains: Vec<String> = Vec::new();
        let mut non_cloudflare_ips: Vec<String> = Vec::new();

        let resolver = StubResolver::new();
        let ipv4_range: IpRange<Ipv4Net> = cf_result.result.ipv4_cidrs.iter().map(|ip| ip.parse().unwrap()).collect();
        let ipv6_range: IpRange<Ipv6Net> = cf_result.result.ipv6_cidrs.iter().map(|ip| ip.parse().unwrap()).collect();

        let mut index = 0;
        while index < targets.len() {
            let target = &targets[index];

            println!("");
            println!("{}[*]{} Querying {:?}", CL::Pink.get(), CL::End.get(), target);

            let a_question = Question::new(target.clone(), Rtype::A, Class::IN);
            let aaaa_question = Question::new(target.clone(), Rtype::AAAA, Class::IN);
            let srv_question = Question::new(target.clone(), Rtype::SRV, Class::IN);
            let ns_question = Question::new(target.clone(), Rtype::NS, Class::IN);
            let cname_question = Question::new(target.clone(), Rtype::CNAME, Class::IN);
            let txt_question = Question::new(target.clone(), Rtype::TXT, Class::IN);
            let mx_question = Question::new(target.clone(), Rtype::MX, Class::IN);

            query(&resolver, a_question, "A", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            query(&resolver, aaaa_question, "AAAA", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            query(&resolver, srv_question, "SRV", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            query(&resolver, ns_question, "NS", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            query(&resolver, cname_question, "CNAME", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            query(&resolver, txt_question, "TXT", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            query(&resolver, mx_question, "MX", &mut targets, &mut non_cloudflare_ips, &mut recursively_found_domains, &ipv4_range, &ipv6_range).await;
            println!("");

            index += 1;

            // going with the unofficial 500-1000 QPS / IP rate limit & 7 queries made per iter
            // we can make ~71 iters per second
            // giving ourselves a little bit of a buffer, we can sleep for 20ms
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
            // tho the queries themselves will most likely take longer than 20ms to complete anyway so we're really not pushing any limits here
        }

        println!("=------------= RESULTS =------------=");
        println!("{}[+]{} Non-Cloudflare IPs found: {}x", CL::DullGreen.get(), CL::End.get(), non_cloudflare_ips.len());
        println!("{}[+]{} Recursively scraped domains: {}x", CL::DullGreen.get(), CL::End.get(), recursively_found_domains.len());
        println!("");
        println!("{}[*]{} Writing results to file...", CL::Pink.get(), CL::End.get());

        // save results to file with domain name as filename
        let ips_filename = format!("results/{}-ips.txt", central_domain);
        let mut ips_file_handler = FileHandler::new(&ips_filename).unwrap();
        ips_file_handler.clear().expect("[!] Failed to clear file");
        for ip in non_cloudflare_ips {
            ips_file_handler.write_line(ip).expect("[!] Failed to write to file");
        }

        let domains_filename = format!("results/{}-domains.txt", central_domain);
        let mut domains_file_handler = FileHandler::new(&domains_filename).unwrap();
        domains_file_handler.clear().expect("[!] Failed to clear file");
        for domain in recursively_found_domains {
            domains_file_handler.write_line(domain).expect("[!] Failed to write to file");
        }

    } else {
        println!("{}[!]{} Failed to get Cloudflare IPs", CL::Red.get(), CL::End.get());
    }
}