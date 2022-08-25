// Copyright 2020 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// const sphinx::constants::PAYLOAD_SIZE: usize = 1024;

#[cfg(test)]
mod create_and_process_sphinx_packet {
    use std::time::Duration;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb() {
        let (node1_sk, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![100u8, 16];
        let sphinx_packet =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
				println!("{:?}", payload.as_bytes());
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_old_to_allnew_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };		

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_old_to_n3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();
		
        match sphinx_packet_y.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_old_to_n2newn3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };
		
		match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_old_to_n2newn3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_z = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();
		
		match sphinx_packet_z.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_new_to_allold_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };		

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_new_to_n3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };	

		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_y.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_new_to_n2oldn3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };			

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb_from_new_to_n2oldn3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );		
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );		
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );		

        let route = [node1, node2, node3];
		let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
		let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );
		let message = vec![13u8, 16];
        let sphinx_packet_x =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
		let sphinx_packet = sphinx::SphinxPacket::from_bytes(&sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		
        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };		

		let sphinx_packet_z = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_z.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();	
                assert_eq!(expected_payload, payload.as_bytes());				
            }
            _ => panic!(),
        };
		
    }
}

#[cfg(test)]
mod converting_sphinx_packet_to_and_from_bytes {
    use std::time::Duration;

    #[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss() {
        let (node1_sk, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet = sphinx::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_old_to_allnew_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_old_to_n3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx_existing::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_y.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_old_to_n2newn3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx_existing::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_old_to_n2newn3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node::new(
            sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx_existing::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx_existing::route::Destination::new(
            sphinx_existing::route::DestinationAddressBytes::from_bytes([3u8; sphinx_existing::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx_existing::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx_existing::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx_existing::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx_existing::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_z = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();
		
		match sphinx_packet_z.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_new_to_allold_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx_existing::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_new_to_n3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_y.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_new_to_n2oldn3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss_from_new_to_n2oldn3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node::new(
            sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = sphinx::header::delays::generate_from_average_duration(route.len(), average_delay);
        let destination = sphinx::route::Destination::new(
            sphinx::route::DestinationAddressBytes::from_bytes([3u8; sphinx::constants::DESTINATION_ADDRESS_LENGTH]),
            [4u8; sphinx::constants::IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            sphinx::SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet_x = sphinx::SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
		
		let recovered_packet = sphinx::SphinxPacket::from_bytes(&recovered_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_z = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_z.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod create_and_process_surb {    
    use std::time::Duration;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx::crypto::EphemeralSecret::new();
        let surb_delays =
            sphinx::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx::surb::SURB::new(
            surb_initial_secret,
            sphinx::surb::SURBMaterial::new(surb_route, surb_delays.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet, first_hop) =
            sphinx::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH])
        );

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays[1]);
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_old_to_allnew_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx_existing::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx_existing::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx_existing::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx_existing::surb::SURB::new(
            surb_initial_secret,
            sphinx_existing::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx_existing::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx_existing::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays[1]);
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_old_to_n3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx_existing::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx_existing::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx_existing::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx_existing::surb::SURB::new(
            surb_initial_secret,
            sphinx_existing::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx_existing::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx_existing::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));
		let mut surb_delays_y = Vec::new();
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays[1]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_y.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_old_to_n2newn3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx_existing::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx_existing::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx_existing::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx_existing::surb::SURB::new(
            surb_initial_secret,
            sphinx_existing::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx_existing::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx_existing::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));
		let mut surb_delays_y = Vec::new();
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays_y[1]);
                next_packet
            }
            _ => panic!(),
        };
		
		match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_old_to_n2newn3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx_existing::crypto::keygen();
        let node1 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx_existing::crypto::keygen();
        let node2 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx_existing::crypto::keygen();
        let node3 = sphinx_existing::route::Node {
            address: sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx_existing::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx_existing::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx_existing::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx_existing::surb::SURB::new(
            surb_initial_secret,
            sphinx_existing::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx_existing::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx_existing::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx_existing::route::NodeAddressBytes::from_bytes([5u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));
		let mut surb_delays_y = Vec::new();
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays_y.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays_y[1]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_z = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();
		
		match sphinx_packet_z.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_new_to_allold_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx::surb::SURB::new(
            surb_initial_secret,
            sphinx::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx_existing::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx_existing::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([4u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays[1]);
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_new_to_n3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx::surb::SURB::new(
            surb_initial_secret,
            sphinx::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));
		let mut surb_delays_y = Vec::new();
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays[1]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_y.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_new_to_n2oldn3old_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx::surb::SURB::new(
            surb_initial_secret,
            sphinx::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx_existing::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));
		let mut surb_delays_y = Vec::new();
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays_y[1]);
                next_packet
            }
            _ => panic!(),
        };		

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            sphinx_existing::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx_existing::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx_existing::constants::PAYLOAD_SIZE - sphinx_existing::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
	
	#[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_from_new_to_n2oldn3new_sphinx_packet() {
        let (node1_sk_x, node1_pk) = sphinx::crypto::keygen();
        let node1 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk_x, node2_pk) = sphinx::crypto::keygen();
        let node2 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk_x, node3_pk) = sphinx::crypto::keygen();
        let node3 = sphinx::route::Node {
            address: sphinx::route::NodeAddressBytes::from_bytes([2u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = sphinx::test_utils::fixtures::destination_fixture();
        let surb_initial_secret = sphinx::crypto::EphemeralSecret::new();
        let surb_delays_x =
            sphinx::header::delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = sphinx::surb::SURB::new(
            surb_initial_secret,
            sphinx::surb::SURBMaterial::new(surb_route, surb_delays_x.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet_x, first_hop) =
            sphinx::surb::SURB::use_surb(pre_surb, &plaintext_message, sphinx::packet::builder::DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            sphinx::route::NodeAddressBytes::from_bytes([5u8; sphinx::constants::NODE_ADDRESS_LENGTH])
        );
		
		let surb_sphinx_packet = sphinx::SphinxPacket::from_bytes(&surb_sphinx_packet_x.to_bytes()).unwrap();
		let node1_sk = sphinx::crypto::PrivateKey::from(node1_sk_x.to_bytes());
		let node2_sk = sphinx_existing::crypto::PrivateKey::from(node2_sk_x.to_bytes());
		let node3_sk = sphinx::crypto::PrivateKey::from(node3_sk_x.to_bytes());
		let mut surb_delays = Vec::new();
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays.push(sphinx::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));
		let mut surb_delays_y = Vec::new();
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[0].to_bytes()));
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[1].to_bytes()));
		surb_delays_y.push(sphinx_existing::header::delays::Delay::from_bytes(surb_delays_x[2].to_bytes()));

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            sphinx::ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    sphinx::route::NodeAddressBytes::from_bytes([4u8; sphinx::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };
		
		let sphinx_packet_y = sphinx_existing::SphinxPacket::from_bytes(&next_sphinx_packet_1.to_bytes()).unwrap();

        let next_sphinx_packet_2 = match sphinx_packet_y.process(&node2_sk).unwrap() {
            sphinx_existing::ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    sphinx_existing::route::NodeAddressBytes::from_bytes([2u8; sphinx_existing::constants::NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays_y[1]);
                next_packet
            }
            _ => panic!(),
        };	

		let sphinx_packet_z = sphinx::SphinxPacket::from_bytes(&next_sphinx_packet_2.to_bytes()).unwrap();

        match sphinx_packet_z.process(&node3_sk).unwrap() {
            sphinx::ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; sphinx::constants::SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; sphinx::constants::PAYLOAD_SIZE - sphinx::constants::SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
}
