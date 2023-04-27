# SandboxTestersV2Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SandboxTesterV2**](SandboxTesterV2.md) |  | 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSandboxTestersV2Response

`func NewSandboxTestersV2Response(data []SandboxTesterV2, links PagedDocumentLinks, ) *SandboxTestersV2Response`

NewSandboxTestersV2Response instantiates a new SandboxTestersV2Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSandboxTestersV2ResponseWithDefaults

`func NewSandboxTestersV2ResponseWithDefaults() *SandboxTestersV2Response`

NewSandboxTestersV2ResponseWithDefaults instantiates a new SandboxTestersV2Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SandboxTestersV2Response) GetData() []SandboxTesterV2`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SandboxTestersV2Response) GetDataOk() (*[]SandboxTesterV2, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SandboxTestersV2Response) SetData(v []SandboxTesterV2)`

SetData sets Data field to given value.


### GetLinks

`func (o *SandboxTestersV2Response) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SandboxTestersV2Response) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SandboxTestersV2Response) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SandboxTestersV2Response) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SandboxTestersV2Response) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SandboxTestersV2Response) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SandboxTestersV2Response) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


