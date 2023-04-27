# CiBuildRunResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiBuildRun**](CiBuildRun.md) |  | 
**Included** | Pointer to [**[]CiBuildRunsResponseIncludedInner**](CiBuildRunsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiBuildRunResponse

`func NewCiBuildRunResponse(data CiBuildRun, links DocumentLinks, ) *CiBuildRunResponse`

NewCiBuildRunResponse instantiates a new CiBuildRunResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunResponseWithDefaults

`func NewCiBuildRunResponseWithDefaults() *CiBuildRunResponse`

NewCiBuildRunResponseWithDefaults instantiates a new CiBuildRunResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiBuildRunResponse) GetData() CiBuildRun`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiBuildRunResponse) GetDataOk() (*CiBuildRun, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiBuildRunResponse) SetData(v CiBuildRun)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiBuildRunResponse) GetIncluded() []CiBuildRunsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiBuildRunResponse) GetIncludedOk() (*[]CiBuildRunsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiBuildRunResponse) SetIncluded(v []CiBuildRunsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiBuildRunResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiBuildRunResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiBuildRunResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiBuildRunResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


