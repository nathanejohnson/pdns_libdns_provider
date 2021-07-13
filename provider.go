// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for <PROVIDER NAME>. TODO: This package is a
// template only. Customize all godocs for actual implementation.
package powerdns

import (
	"context"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with PowerDNS.
type Provider struct {
	ServerURL string `json:"server_url"`
	ServerID  string `json:"server_id"`
	APIToken  string `json:"api_token,omitempty"`
	mu        sync.Mutex
	c         *Client
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	prec, err := c.fullZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	recs := make([]libdns.Record, 0, len(prec.ResourceRecordSets))
	for _, rec := range prec.ResourceRecordSets {
		for _, v := range rec.Records {
			recs = append(recs, libdns.Record{
				ID:       prec.ID,
				Type:     rec.Type,
				Name:     rec.Name,
				Value:    v.Content,
				TTL:      time.Second * time.Duration(rec.TTL),
				Priority: 0,
			})
		}
	}
	return recs, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	pZone, err := c.fullZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	rrecs, err := c.mergeRRecs(pZone, records)
	if err != nil {
		return nil, err
	}
	err = c.updateRRs(ctx, pZone.ID, rrecs)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	zID, err := c.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	inHash := makeLDRecHash(records)
	rRecs := convertHash(inHash)
	err = c.updateRRs(ctx, zID, rRecs)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	pZone, err := c.fullZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	rRSets := cullRRecs(pZone, records)
	err = c.updateRRs(ctx, pZone.ID, rRSets)
	if err != nil {
		return nil, err
	}

	return records, nil

}

func (p *Provider) client() (*Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c == nil {
		var err error
		p.c, err = NewClient(p.ServerID, p.ServerURL, p.APIToken)
		if err != nil {
			return nil, err
		}
	}
	return p.c, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
