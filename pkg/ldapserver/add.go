package ldapserver

import (
	"errors"
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func HandleAddRequest(req *ber.Packet, boundDN string, server *Server, conn net.Conn) (resultCode LDAPResultCode) {
	parsed, _ := parseAddRequest("", req)
	fnNames := []string{}
	for k := range server.AddFns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(parsed.DN, fnNames)
	server.AddFns[fn].Add(boundDN, parsed, conn)
	return ldap.LDAPResultSuccess
}

func parseAddRequest(boundDN string, req *ber.Packet) (*ldap.AddRequest, error) {
	if len(req.Children) != 2 {
		return &ldap.AddRequest{}, ldap.NewError(ldap.LDAPResultOperationsError, errors.New("Bad add request"))
	}

	entrydn := req.Children[0].Value.(string)

	attrs := parseAttributeList(req.Children[1])
	log.Printf("AddRequest dn: %s, attributes %v", entrydn, attrs)
	return &ldap.AddRequest{DN: entrydn, Attributes: attrs}, nil
}

func parseAttributeList(req *ber.Packet) []ldap.Attribute {
	ldapAttrs := []ldap.Attribute{}

	for _, attr := range req.Children {
		attrType := attr.Children[0].Value.(string)
		log.Printf("Type %s", attrType)
		values := []string{}
		for _, value := range attr.Children[1].Children {
			values = append(values, value.Value.(string))
			log.Printf("Values  %v", values)
		}
		ldapAttrs = append(ldapAttrs, ldap.Attribute{attrType, values})
	}
	return ldapAttrs
}
