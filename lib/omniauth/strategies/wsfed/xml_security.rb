# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require "rubygems"
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "nokogiri"
require "digest/sha1"
require "digest/sha2"

module OmniAuth
  module Strategies
    class WSFed

      module XMLSecurity

        class SignedDocument < REXML::Document

          DSIG = "http://www.w3.org/2000/09/xmldsig#"
          NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET

          attr_accessor :signed_element_id, :settings

          def initialize(response, settings = {})
            super(response)
            extract_signed_element_id

            self.settings = settings
          end

          def validate(idp_cert_fingerprint, soft = true)
            # get cert from response
            base64_cert = Utils.element_text(REXML::XPath.first(self,"//ds:X509Certificate", {"ds" => DSIG}))
            cert_text   = Base64.decode64(base64_cert)
            cert        = OpenSSL::X509::Certificate.new(cert_text)

            # check cert matches registered idp cert
            fingerprint = Digest::SHA1.hexdigest(cert.to_der)

            if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
              return soft ? false : (raise OmniAuth::Strategies::WSFed::ValidationError.new("Fingerprint mismatch"))
            end

            validate_doc(base64_cert, soft)
          end

          def validate_doc(base64_cert, soft = true)

            document = Nokogiri::XML(self.to_s) do |config|
              config.options = NOKOGIRI_OPTIONS
            end

            # validate references

            # check for inclusive namespaces

            inclusive_namespaces            = []
            inclusive_namespace_element     = REXML::XPath.first(self, "//ec:InclusiveNamespaces")

            if inclusive_namespace_element
              prefix_list                   = inclusive_namespace_element.attributes.get_attribute('PrefixList').value
              inclusive_namespaces          = prefix_list.split(" ")
            end

            sig_element = REXML::XPath.first(self, "//ds:Signature", {"ds"=>DSIG})

            # canonicalization method
            canonicalization_method_element = REXML::XPath.first(sig_element, "./ds:SignedInfo/ds:CanonicalizationMethod","ds" => DSIG )
            canon_algorithm = canon_algorithm(canonicalization_method_element)

            noko_sig_element = document.at_xpath('//ds:Signature', 'ds' => DSIG)
            noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => DSIG)

            canon_string = noko_signed_info_element.canonicalize(canon_algorithm)
            noko_sig_element.remove

            # remove signature node
            sig_element.remove

            # verify signature
            signed_info_element     = REXML::XPath.first(sig_element, "./ds:SignedInfo", {"ds"=>DSIG})
            signed_info_element.attributes['xmlns'] = DSIG

            # check digests
            #saml_version = settings[:saml_version]
            ref = REXML::XPath.first(signed_info_element, "./ds:Reference", {"ds"=>DSIG})

            uri                           = ref.attributes.get_attribute("URI").value
            reference_nodes               = document.xpath("//*[@ID=$uri]", nil, { "uri" => uri[1,uri.size] }) ||
                                            document.xpath("//*[@AssertionID=$uri]", nil, { "uri" => uri[1,uri.size] })

            if reference_nodes.length > 1 # ensures no elements with same ID to prevent signature wrapping attack.
              return soft ? false : (raise OmniAuth::Strategies::WSFed::ValidationError.new("Digest Mismatch"))
            end

            hashed_element = reference_nodes[0]

            canon_hashed_element          = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)
            digest_algorithm              = algorithm(REXML::XPath.first(ref, "./ds:DigestMethod", {"ds"=>DSIG}))
            hash                          = Base64.encode64(digest_algorithm.digest(canon_hashed_element)).chomp
            digest_value                  = Utils.element_text(REXML::XPath.first(ref, "./ds:DigestValue", {"ds"=>DSIG}))

            unless digests_match?(hash, digest_value)

              return soft ? false : (raise OmniAuth::Strategies::WSFed::ValidationError.new("Digest mismatch"))
            end

            base64_signature        = Utils.element_text(REXML::XPath.first(sig_element, "//ds:SignatureValue", {"ds"=>DSIG}))
            signature               = Base64.decode64(base64_signature)

            # get certificate object
            cert_text               = Base64.decode64(base64_cert)
            cert                    = OpenSSL::X509::Certificate.new(cert_text)

            # signature method
            signature_algorithm     = algorithm(REXML::XPath.first(signed_info_element, "//ds:SignatureMethod", {"ds"=>DSIG}))

            unless cert.public_key.verify(signature_algorithm.new, signature, canon_string)
              return soft ? false : (raise OmniAuth::Strategies::WSFed::ValidationError.new("Key validation error"))
            end

            return true
          end

        private

          def digests_match?(hash, digest_value)
            hash == digest_value
          end

          def extract_signed_element_id
            reference_element       = REXML::XPath.first(self, "//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
            self.signed_element_id  = reference_element.attribute("URI").value unless reference_element.nil?
          end

          def algorithm(element)
            algorithm = element.attribute("Algorithm").value if element

            algorithm = algorithm && algorithm =~ /sha(.*?)$/i && $1.to_i
            case algorithm
            when 256 then OpenSSL::Digest::SHA256
            when 384 then OpenSSL::Digest::SHA384
            when 512 then OpenSSL::Digest::SHA512
            else
              OpenSSL::Digest::SHA1
            end
          end

          def canon_algorithm(element)
            algorithm = element
            if algorithm.is_a?(REXML::Element)
              algorithm = element.attribute('Algorithm').value
            end

            case algorithm
              when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                   "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
                Nokogiri::XML::XML_C14N_1_0
              when "http://www.w3.org/2006/12/xml-c14n11",
                   "http://www.w3.org/2006/12/xml-c14n11#WithComments"
                Nokogiri::XML::XML_C14N_1_1
              else
                Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
            end
          end

        end
      end
    end
  end
end

