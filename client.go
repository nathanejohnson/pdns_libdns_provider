package powerdns

import (
	"context"
	"fmt"

	"github.com/libdns/libdns"
	pdns "github.com/mittwald/go-powerdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

type Client struct {
	sID string
	pdns.Client
}

func NewClient(ServerID, ServerURL, APIToken string) (*Client, error) {
	c, err := pdns.New(
		pdns.WithBaseURL(ServerURL),
		pdns.WithAPIKeyAuthentication(APIToken),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		sID:    ServerID,
		Client: c,
	}, nil
}

func (c *Client) updateRRs(ctx context.Context, zoneID string, recs []zones.ResourceRecordSet) error {
	for _, rec := range recs {
		err := c.Zones().AddRecordSetToZone(ctx, c.sID, zoneID, rec)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) mergeRRecs(fullZone *zones.Zone, records []libdns.Record) ([]zones.ResourceRecordSet, error) {
	// pdns doesn't really have an append functionality, so we have to fake it by
	// fetching existing rrsets for the zone and see if any already exist.  If so,
	// merge those with the existing data.  Otherwise just add the record.
	inHash := makeLDRecHash(records)
	var rrsets []zones.ResourceRecordSet
	// Merge existing resource record sets with any that were passed in to modify.
	for _, t := range fullZone.ResourceRecordSets {
		k := key(t.Name, t.Type)
		if recs, ok := inHash[k]; ok && len(recs) > 0 {
			rr := zones.ResourceRecordSet{
				Name:       t.Name,
				Type:       t.Type,
				TTL:        int(recs[0].TTL.Seconds()),
				ChangeType: zones.ChangeTypeReplace,
				Comments:   t.Comments,
			}
			rr.Records = make([]zones.Record, len(rr.Records))
			copy(rr.Records, t.Records)
			// squash duplicate values
			dupes := make(map[string]bool)
			for _, prec := range t.Records {
				dupes[prec.Content] = true
			}
			// now for our additions
			for _, rec := range recs {
				if !dupes[rec.Value] {
					rr.Records = append(rr.Records, zones.Record{
						Content: rec.Value,
					})
					dupes[rec.Value] = true
				}
			}
			rrsets = append(rrsets, rr)
			delete(inHash, k)
		}
	}
	// Any remaining in our input hash need to be straight adds / creates.
	rrsets = append(rrsets, convertHash(inHash)...)
	return rrsets, nil
}

func cullRRecs(fullZone *zones.Zone, records []libdns.Record) []zones.ResourceRecordSet {
	inHash := makeLDRecHash(records)
	var rRSets []zones.ResourceRecordSet
	for _, t := range fullZone.ResourceRecordSets {
		k := key(t.Name, t.Type)
		if recs, ok := inHash[k]; ok && len(recs) > 0 {
			rRec := &zones.ResourceRecordSet{
				Name: t.Name,
				Type: t.Type,
			}
			rr := removeRecords(t, recs)
			if len(rr.Records) == 0 {
				rRec.ChangeType = zones.ChangeTypeDelete
			} else {
				rRec.ChangeType = zones.ChangeTypeReplace
				rRec.TTL = t.TTL
				rRec.Comments = t.Comments
			}
			rRSets = append(rRSets, *rRec)
		}
	}
	return rRSets

}

func removeRecords(rRSet zones.ResourceRecordSet, culls []libdns.Record) zones.ResourceRecordSet {
	deleteItem := func(item string) []zones.Record {
		recs := rRSet.Records
		for i := len(recs) - 1; i >= 0; i-- {
			if recs[i].Content == item {
				copy(recs[i:], recs[:i+1])
				recs = recs[:len(recs)-1]
			}
		}
		return recs
	}
	for _, c := range culls {
		rRSet.Records = deleteItem(c.Value)
	}
	return rRSet
}

func convertHash(inHash map[string][]libdns.Record) []zones.ResourceRecordSet {
	var rrsets []zones.ResourceRecordSet
	for _, recs := range inHash {
		if len(recs) == 0 {
			continue
		}
		rr := zones.ResourceRecordSet{
			Name:       recs[0].Name,
			Type:       recs[0].Type,
			TTL:        int(recs[0].TTL.Seconds()),
			ChangeType: zones.ChangeTypeReplace,
		}
		for _, rec := range recs {
			rr.Records = append(rr.Records, zones.Record{
				Content: rec.Value,
			})
		}
		rrsets = append(rrsets, rr)
	}
	return rrsets
}

func key(Name, Type string) string {
	return Name + ":" + Type
}

func makeLDRecHash(records []libdns.Record) map[string][]libdns.Record {
	// Keep track of records grouped by name + type
	inHash := make(map[string][]libdns.Record)

	for _, r := range records {
		k := key(r.Name, r.Type)
		inHash[k] = append(inHash[k], r)
	}
	return inHash
}

func (c *Client) fullZone(ctx context.Context, zoneName string) (*zones.Zone, error) {

	zc := c.Zones()
	shortZone, err := c.shortZone(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	pzone, err := zc.GetZone(ctx, c.sID, shortZone.ID)
	if err != nil {
		return nil, err
	}
	return pzone, nil
}

func (c *Client) shortZone(ctx context.Context, zoneName string) (*zones.Zone, error) {
	zc := c.Zones()
	pzones, err := zc.ListZone(ctx, c.sID, zoneName)
	if err != nil {
		return nil, err
	}
	if len(pzones) != 1 {
		return nil, fmt.Errorf("zone not found")
	}
	return &pzones[0], nil
}

func (c *Client) zoneID(ctx context.Context, zoneName string) (string, error) {
	shortZone, err := c.shortZone(ctx, zoneName)
	if err != nil {
		return "", err
	}
	return shortZone.ID, nil
}
