# CiBuildActionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiBuildAction**](CiBuildAction.md) |  | 
**Included** | Pointer to [**[]CiBuildRun**](CiBuildRun.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiBuildActionResponse

`func NewCiBuildActionResponse(data CiBuildAction, links DocumentLinks, ) *CiBuildActionResponse`

NewCiBuildActionResponse instantiates a new CiBuildActionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildActionResponseWithDefaults

`func NewCiBuildActionResponseWithDefaults() *CiBuildActionResponse`

NewCiBuildActionResponseWithDefaults instantiates a new CiBuildActionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiBuildActionResponse) GetData() CiBuildAction`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiBuildActionResponse) GetDataOk() (*CiBuildAction, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiBuildActionResponse) SetData(v CiBuildAction)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiBuildActionResponse) GetIncluded() []CiBuildRun`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiBuildActionResponse) GetIncludedOk() (*[]CiBuildRun, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiBuildActionResponse) SetIncluded(v []CiBuildRun)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiBuildActionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiBuildActionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiBuildActionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiBuildActionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


