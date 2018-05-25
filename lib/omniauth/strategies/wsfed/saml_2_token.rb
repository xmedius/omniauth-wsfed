module OmniAuth
  module Strategies
    class WSFed
      class SAML2Token

        attr_accessor :document

        def initialize(document)
          @document = document
        end

        def audience
          applies_to = REXML::XPath.first(document, '//t:RequestSecurityTokenResponse/wsp:AppliesTo', { 't' => WS_TRUST, 'wsp' => WS_POLICY })
          Utils.element_text(REXML::XPath.first(applies_to, '//wsa:EndpointReference/wsa:Address', { 'wsa' => WS_ADDRESSING }))
        end

        def issuer
          Utils.element_text(REXML::XPath.first(document, '//Assertion/Issuer'))
        end

        def claims
          stmt_element = REXML::XPath.first(document, '//Assertion/AttributeStatement')

          return {} if stmt_element.nil?

          {}.tap do |result|
            stmt_element.elements.each do |attr_element|
              name  = attr_element.attributes['Name']

              if attr_element.elements.count > 1
                value = []
                attr_element.elements.each { |element| value << Utils.element_text(element) }
              else
                value = Utils.element_text(attr_element.elements.first).to_s.lstrip.rstrip
              end

              result[name] = value
            end
          end
        end

      end
    end
  end
end
