package cashu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

/*
OpenAPI Specification for Cashu Wallet REST API
{"openapi":"3.1.0","info":{"title":"Cashu Wallet REST API","description":"REST API for Cashu Nutshell","license":{"name":"MIT License","url":"https://raw.githubusercontent.com/cashubtc/cashu/main/LICENSE"},"version":"0.13.0"},"paths":{"/pay":{"post":{"summary":"Pay Lightning Invoice","operationId":"Pay_lightning_invoice_pay_post","parameters":[{"description":"Lightning invoice to pay","required":true,"schema":{"type":"string","title":"Invoice","description":"Lightning invoice to pay"},"name":"invoice","in":"query"},{"description":"Mint URL to pay from (None for default mint)","required":false,"schema":{"type":"string","title":"Mint","description":"Mint URL to pay from (None for default mint)"},"name":"mint","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/PayResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/invoice":{"post":{"summary":"Request Lightning Invoice","operationId":"Request_lightning_invoice_invoice_post","parameters":[{"description":"Amount to request in invoice","required":true,"schema":{"type":"integer","title":"Amount","description":"Amount to request in invoice"},"name":"amount","in":"query"},{"description":"Hash of paid invoice","required":false,"schema":{"type":"string","title":"Hash","description":"Hash of paid invoice"},"name":"hash","in":"query"},{"description":"Mint URL to create an invoice at (None for default mint)","required":false,"schema":{"type":"string","title":"Mint","description":"Mint URL to create an invoice at (None for default mint)"},"name":"mint","in":"query"},{"description":"Split minted tokens with a specific amount.","required":false,"schema":{"type":"integer","title":"Split","description":"Split minted tokens with a specific amount."},"name":"split","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/InvoiceResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/balance":{"get":{"summary":"Display balance.","operationId":"Balance_balance_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/BalanceResponse"}}}}}}},"/send":{"post":{"summary":"Send Tokens","operationId":"Send_tokens_send_post","parameters":[{"description":"Amount to send","required":true,"schema":{"type":"integer","title":"Amount","description":"Amount to send"},"name":"amount","in":"query"},{"description":"Send to nostr pubkey","required":false,"schema":{"type":"string","title":"Nostr","description":"Send to nostr pubkey"},"name":"nostr","in":"query"},{"description":"Lock tokens (P2SH)","required":false,"schema":{"type":"string","title":"Lock","description":"Lock tokens (P2SH)"},"name":"lock","in":"query"},{"description":"Mint URL to send from (None for default mint)","required":false,"schema":{"type":"string","title":"Mint","description":"Mint URL to send from (None for default mint)"},"name":"mint","in":"query"},{"description":"Do not split tokens before sending.","required":false,"schema":{"type":"boolean","title":"Nosplit","description":"Do not split tokens before sending.","default":false},"name":"nosplit","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/SendResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/receive":{"post":{"summary":"Receive Tokens","operationId":"Receive_tokens_receive_post","parameters":[{"description":"Token to receive","required":false,"schema":{"type":"string","title":"Token","description":"Token to receive"},"name":"token","in":"query"},{"description":"Receive tokens via nostr","required":false,"schema":{"type":"boolean","title":"Nostr","description":"Receive tokens via nostr","default":false},"name":"nostr","in":"query"},{"description":"Receive all pending tokens","required":false,"schema":{"type":"boolean","title":"All","description":"Receive all pending tokens","default":false},"name":"all","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/ReceiveResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/burn":{"post":{"summary":"Burn Spent Tokens","operationId":"Burn_spent_tokens_burn_post","parameters":[{"description":"Token to burn","required":false,"schema":{"type":"string","title":"Token","description":"Token to burn"},"name":"token","in":"query"},{"description":"Burn all spent tokens","required":false,"schema":{"type":"boolean","title":"All","description":"Burn all spent tokens","default":false},"name":"all","in":"query"},{"description":"Force check on all tokens.","required":false,"schema":{"type":"boolean","title":"Force","description":"Force check on all tokens.","default":false},"name":"force","in":"query"},{"description":"Forcefully delete pending token by send ID if mint is unavailable","required":false,"schema":{"type":"string","title":"Delete","description":"Forcefully delete pending token by send ID if mint is unavailable"},"name":"delete","in":"query"},{"description":"Mint URL to burn from (None for default mint)","required":false,"schema":{"type":"string","title":"Mint","description":"Mint URL to burn from (None for default mint)"},"name":"mint","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/BurnResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/pending":{"get":{"summary":"Show Pending Tokens","operationId":"Show_pending_tokens_pending_get","parameters":[{"description":"Show only n pending tokens","required":false,"schema":{"type":"integer","title":"Number","description":"Show only n pending tokens"},"name":"number","in":"query"},{"description":"Show pending tokens only starting from offset","required":false,"schema":{"type":"integer","title":"Offset","description":"Show pending tokens only starting from offset","default":0},"name":"offset","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/PendingResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/lock":{"get":{"summary":"Generate Receiving Lock","operationId":"Generate_receiving_lock_lock_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/LockResponse"}}}}}}},"/locks":{"get":{"summary":"Show Unused Receiving Locks","operationId":"Show_unused_receiving_locks_locks_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/LocksResponse"}}}}}}},"/invoices":{"get":{"summary":"List All Pending Invoices","operationId":"List_all_pending_invoices_invoices_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/InvoicesResponse"}}}}}}},"/wallets":{"get":{"summary":"List All Available Wallets","operationId":"List_all_available_wallets_wallets_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/WalletsResponse"}}}}}}},"/restore":{"post":{"summary":"Restore Wallet","operationId":"Restore_wallet_restore_post","parameters":[{"description":"Counter to which restore the wallet","required":true,"schema":{"type":"integer","title":"To","description":"Counter to which restore the wallet"},"name":"to","in":"query"}],"responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/RestoreResponse"}}}},"422":{"description":"Validation Error","content":{"application/json":{"schema":{"$ref":"#/components/schemas/HTTPValidationError"}}}}}}},"/info":{"get":{"summary":"Information About Cashu Wallet","operationId":"Information_about_Cashu_wallet_info_get","responses":{"200":{"description":"Successful Response","content":{"application/json":{"schema":{"$ref":"#/components/schemas/InfoResponse"}}}}}}}},"components":{"schemas":{"BalanceResponse":{"properties":{"balance":{"type":"integer","title":"Balance"},"keysets":{"type":"object","title":"Keysets"},"mints":{"type":"object","title":"Mints"}},"type":"object","required":["balance"],"title":"BalanceResponse"},"BurnResponse":{"properties":{"balance":{"type":"integer","title":"Balance"}},"type":"object","required":["balance"],"title":"BurnResponse"},"HTTPValidationError":{"properties":{"detail":{"items":{"$ref":"#/components/schemas/ValidationError"},"type":"array","title":"Detail"}},"type":"object","title":"HTTPValidationError"},"InfoResponse":{"properties":{"version":{"type":"string","title":"Version"},"wallet":{"type":"string","title":"Wallet"},"debug":{"type":"boolean","title":"Debug"},"cashu_dir":{"type":"string","title":"Cashu Dir"},"mint_urls":{"items":{"type":"string"},"type":"array","title":"Mint Urls","default":[]},"settings":{"type":"string","title":"Settings"},"tor":{"type":"boolean","title":"Tor"},"nostr_public_key":{"type":"string","title":"Nostr Public Key"},"nostr_relays":{"items":{"type":"string"},"type":"array","title":"Nostr Relays","default":[]},"socks_proxy":{"type":"string","title":"Socks Proxy"}},"type":"object","required":["version","wallet","debug","cashu_dir","tor"],"title":"InfoResponse"},"Invoice":{"properties":{"amount":{"type":"integer","title":"Amount"},"pr":{"type":"string","title":"Pr"},"hash":{"type":"string","title":"Hash"},"payment_hash":{"type":"string","title":"Payment Hash"},"preimage":{"type":"string","title":"Preimage"},"issued":{"type":"boolean","title":"Issued","default":false},"paid":{"type":"boolean","title":"Paid","default":false},"time_created":{"anyOf":[{"type":"string"},{"type":"integer"},{"type":"number"}],"title":"Time Created","default":""},"time_paid":{"anyOf":[{"type":"string"},{"type":"integer"},{"type":"number"}],"title":"Time Paid","default":""}},"type":"object","required":["amount","pr","hash"],"title":"Invoice"},"InvoiceResponse":{"properties":{"amount":{"type":"integer","title":"Amount"},"invoice":{"$ref":"#/components/schemas/Invoice"},"hash":{"type":"string","title":"Hash"}},"type":"object","title":"InvoiceResponse"},"InvoicesResponse":{"properties":{"invoices":{"items":{"$ref":"#/components/schemas/Invoice"},"type":"array","title":"Invoices"}},"type":"object","required":["invoices"],"title":"InvoicesResponse"},"LockResponse":{"properties":{"P2SH":{"type":"string","title":"P2Sh"}},"type":"object","title":"LockResponse"},"LocksResponse":{"properties":{"locks":{"items":{"$ref":"#/components/schemas/P2SHScript"},"type":"array","title":"Locks"}},"type":"object","required":["locks"],"title":"LocksResponse"},"P2SHScript":{"properties":{"script":{"type":"string","title":"Script"},"signature":{"type":"string","title":"Signature"},"address":{"type":"string","title":"Address"}},"type":"object","required":["script","signature"],"title":"P2SHScript","description":"Unlocks P2SH spending condition of a Proof"},"PayResponse":{"properties":{"amount":{"type":"integer","title":"Amount"},"fee":{"type":"integer","title":"Fee"},"amount_with_fee":{"type":"integer","title":"Amount With Fee"}},"type":"object","required":["amount","fee","amount_with_fee"],"title":"PayResponse"},"PendingResponse":{"properties":{"pending_token":{"type":"object","title":"Pending Token"}},"type":"object","required":["pending_token"],"title":"PendingResponse"},"ReceiveResponse":{"properties":{"initial_balance":{"type":"integer","title":"Initial Balance"},"balance":{"type":"integer","title":"Balance"}},"type":"object","required":["initial_balance","balance"],"title":"ReceiveResponse"},"RestoreResponse":{"properties":{"balance":{"type":"integer","title":"Balance"}},"type":"object","required":["balance"],"title":"RestoreResponse"},"SendResponse":{"properties":{"balance":{"type":"integer","title":"Balance"},"token":{"type":"string","title":"Token"},"npub":{"type":"string","title":"Npub"}},"type":"object","required":["balance","token"],"title":"SendResponse"},"ValidationError":{"properties":{"loc":{"items":{"anyOf":[{"type":"string"},{"type":"integer"}]},"type":"array","title":"Location"},"msg":{"type":"string","title":"Message"},"type":{"type":"string","title":"Error Type"}},"type":"object","required":["loc","msg","type"],"title":"ValidationError"},"WalletsResponse":{"properties":{"wallets":{"type":"object","title":"Wallets"}},"type":"object","required":["wallets"],"title":"WalletsResponse"}}}}
*/

// Client manages communication with the API.
type CashuApiClient struct {
	BaseURL    *url.URL     // Base URL for API requests
	httpClient *http.Client // Customized HTTP client
}

// NewCashuApiClient creates a new API client instance.
func NewCashuApiClient(httpClient *http.Client, baseURL string) *CashuApiClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	parsedURL, _ := url.Parse(baseURL)

	return &CashuApiClient{
		BaseURL:    parsedURL,
		httpClient: httpClient,
	}
}

// handleErr is a helper function to handle common HTTP errors.
func (c *CashuApiClient) handleErr(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	return nil
}

// BalanceResponse represents the response from the /balance endpoint.
type BalanceResponse struct {
	Balance int `json:"balance"`
}

// GetBalance returns the current balance.
func (c *CashuApiClient) GetBalance() (*BalanceResponse, error) {
	rel := &url.URL{Path: "/balance"}
	u := c.BaseURL.ResolveReference(rel)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = c.handleErr(resp)
	if err != nil {
		return nil, err
	}
	var response BalanceResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// InvoiceRequest represents the request payload for the /invoice endpoint.
type InvoiceRequest struct {
	Amount int64  `json:"amount"`
	Hash   string `json:"hash,omitempty"`
	Mint   string `json:"mint,omitempty"`
	Split  int    `json:"split,omitempty"`
}

// InvoiceResponse represents the response from the /invoice endpoint.
type InvoiceResponse struct {
	Amount  int64   `json:"amount"`
	Invoice Invoice `json:"invoice"`
	Hash    string  `json:"hash"`
}

// Invoice contains the details of an invoice.
type Invoice struct {
	Amount      int64  `json:"amount"`
	Pr          string `json:"pr"`
	Hash        string `json:"hash"`
	PaymentHash string `json:"payment_hash"`
	Preimage    string `json:"preimage"`
	Issued      bool   `json:"issued"`
	Paid        bool   `json:"paid"`
	TimeCreated string `json:"time_created"`
	TimePaid    string `json:"time_paid"`
}

// CreateInvoice creates a new invoice.
func (c *CashuApiClient) CreateInvoice(request InvoiceRequest) (*InvoiceResponse, error) {
	rel := &url.URL{Path: "/invoice"}
	u := c.BaseURL.ResolveReference(rel)

	values := url.Values{}
	values.Add("amount", strconv.FormatInt(request.Amount, 10))
	if request.Split > 0 {
		values.Add("split", strconv.Itoa(request.Split))
	}

	u.RawQuery = values.Encode()
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = c.handleErr(resp)
	if err != nil {
		return nil, err
	}
	var response InvoiceResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// SendRequest represents the parameters for the `/send` endpoint.
type SendRequest struct {
	Amount  int64  `json:"amount"`
	Nostr   string `json:"nostr,omitempty"`
	Lock    string `json:"lock,omitempty"`
	Mint    string `json:"mint,omitempty"`
	Nosplit bool   `json:"nosplit,omitempty"`
}

// SendResponse represents the response from the `/send` endpoint.
type SendResponse struct {
	Balance int    `json:"balance"`
	Token   string `json:"token"`
	Npub    string `json:"npub"`
}

func (c *CashuApiClient) SendToken(request SendRequest) (*SendResponse, error) {
	rel := &url.URL{Path: "/send"}
	u := c.BaseURL.ResolveReference(rel)

	values := url.Values{}
	values.Add("amount", strconv.FormatInt(request.Amount, 10))
	if request.Nosplit {
		values.Add("nosplit", strconv.FormatBool(request.Nosplit))
	}

	u.RawQuery = values.Encode()
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = c.handleErr(resp)
	if err != nil {
		return nil, err
	}
	var response SendResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil

}

// /receive

type ReceiveResponse struct {
	InitialBalance int `json:"initial_balance"`
	Balance        int `json:"balance"`
}

type ReceiveParameters struct {
	Token *string `json:"token"`
	Lock  *string `json:"lock,omitempty"`
	Nostr *bool   `json:"nostr,omitempty"`
	All   *bool   `json:"all,omitempty"`
}

func (c *CashuApiClient) Receive(params ReceiveParameters) (*ReceiveResponse, error) {
	rel := &url.URL{Path: "/receive"}
	u := c.BaseURL.ResolveReference(rel)

	values := url.Values{}
	if params.Token != nil {
		values.Add("token", *params.Token)
	}
	if params.Lock != nil {
		values.Add("lock", *params.Lock)
	}
	if params.Nostr != nil {
		values.Add("nostr", strconv.FormatBool(*params.Nostr))
	}
	if params.All != nil {
		values.Add("all", strconv.FormatBool(*params.All))
	}

	u.RawQuery = values.Encode()

	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = c.handleErr(resp)
	if err != nil {
		return nil, err
	}
	var receiveResponse ReceiveResponse
	err = json.NewDecoder(resp.Body).Decode(&receiveResponse)
	if err != nil {
		return nil, err
	}

	return &receiveResponse, nil
}

func main() {
	baseURLClient := "http://localhost:4448"
	client := NewCashuApiClient(nil, baseURLClient)

	baseURLRelay := "http://localhost:4448"
	clientRelay := NewCashuApiClient(nil, baseURLRelay)

	// get balance and print
	balance, err := client.GetBalance()
	if err != nil {
		fmt.Println("Balance Error:", err)
		return
	}
	fmt.Printf("Balance: %+v\n", balance.Balance)

	invoice_request := InvoiceRequest{Amount: 100}
	resp, err := client.CreateInvoice(invoice_request)
	if err != nil {
		fmt.Println("Invoice Error:", err)
		return
	}

	fmt.Printf("Invoice: %+v\n", resp.Invoice.Pr)

	send_request := SendRequest{Amount: 1}
	send_resp, err := client.SendToken(send_request)
	if err != nil {
		fmt.Println("Send Error:", err)
		return
	}

	fmt.Printf("Token: %+v\n", send_resp.Token)

	// get balance and print
	balance, err = client.GetBalance()
	if err != nil {
		fmt.Println("Balance Error:", err)
		return
	}
	fmt.Printf("Balance: %+v\n", balance.Balance)

	receive_resp, err := clientRelay.Receive(ReceiveParameters{Token: &send_resp.Token})
	if err != nil {
		fmt.Println("Receive Error:", err)
		return
	}
	fmt.Printf("Received. New balance: %+v\n", receive_resp.Balance)
}
