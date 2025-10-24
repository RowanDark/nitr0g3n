package filters

import "fmt"

func ExampleIsCDNResponse() {
	records := map[string][]string{"CNAME": []string{"assets.cloudfront.net"}}
	fmt.Println(IsCDNResponse(records))
	// Output: true
}
