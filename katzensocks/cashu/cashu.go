package cashu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

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
	Ok             bool   `json:"ok"`
	CheckingId     string `json:"checking_id"`
	PaymentRequest string `json:"payment_request"`
	ErrorMessage   string `json:"error_message"`
}

type PaymentStatus struct {
	Paid     bool   `json:"paid"`
	FeeMsat  int64  `json:"fee_msat"`
	Preimage string `json:"preimage"`
}

// Invoice contains the details of an invoice.
type Invoice struct {
	Amount         int64  `json:"amount"`
	PaymentRequest string `json:"payment_request"`
	Hash           string `json:"hash"`
	PaymentHash    string `json:"payment_hash"`
	Preimage       string `json:"preimage"`
	Issued         bool   `json:"issued"`
	Paid           bool   `json:"paid"`
	TimeCreated    string `json:"time_created"`
	TimePaid       string `json:"time_paid"`
}

func (c *CashuApiClient) CheckInvoice(invoiceResponse InvoiceResponse) (*PaymentStatus, error) {
	rel := &url.URL{Path: "/lightning/invoice_state"}
	u := c.BaseURL.ResolveReference(rel)

	values := url.Values{}
	values.Add("payment_hash", invoiceResponse.CheckingId)
	u.RawQuery = values.Encode()
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
	var response PaymentStatus
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// CreateInvoice creates a new invoice.
func (c *CashuApiClient) CreateInvoice(request InvoiceRequest) (*InvoiceResponse, error) {
	rel := &url.URL{Path: "/lightning/create_invoice"}
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

	go func() {
		fmt.Printf("Checking invoice %s\n", response.CheckingId)
		for {
			paymentStatus, err := c.CheckInvoice(response)
			if err != nil {
				fmt.Println("Error checking invoice:", err)
				return
			}
			if paymentStatus.Paid {
				fmt.Println("Invoice paid!")
				return
			} else {
				fmt.Println("Invoice not paid yet")
			}
		}
	}()

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
	// if request.Nosplit {
	// 	values.Add("nosplit", strconv.FormatBool(request.Nosplit))
	// }

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

	// baseURLRelay := "http://localhost:4448"
	// clientRelay := NewCashuApiClient(nil, baseURLRelay)

	// get balance and print
	balance, err := client.GetBalance()
	if err != nil {
		fmt.Println("Balance Error:", err)
		return
	}
	fmt.Printf("Balance: %+v\n", balance.Balance)

	// invoice_request := InvoiceRequest{Amount: 100}
	// resp, err := client.CreateInvoice(invoice_request)
	// if err != nil {
	// 	fmt.Println("Invoice Error:", err)
	// 	return
	// }

	// fmt.Printf("Invoice: %+v\n", resp.PaymentRequest)

	// // get balance and print
	// balance, err = client.GetBalance()
	// if err != nil {
	// 	fmt.Println("Balance Error:", err)
	// 	return
	// }
	// fmt.Printf("Balance: %+v\n", balance.Balance)

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

	// receive_resp, err := clientRelay.Receive(ReceiveParameters{Token: &send_resp.Token})
	// if err != nil {
	// 	fmt.Println("Receive Error:", err)
	// 	return
	// }
	// fmt.Printf("Received. New balance: %+v\n", receive_resp.Balance)
}
