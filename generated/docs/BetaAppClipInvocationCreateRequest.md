# BetaAppClipInvocationCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**BetaAppClipInvocationCreateRequestData**](BetaAppClipInvocationCreateRequestData.md) |  | 
**Included** | Pointer to [**[]BetaAppClipInvocationLocalizationInlineCreate**](BetaAppClipInvocationLocalizationInlineCreate.md) |  | [optional] 

## Methods

### NewBetaAppClipInvocationCreateRequest

`func NewBetaAppClipInvocationCreateRequest(data BetaAppClipInvocationCreateRequestData, ) *BetaAppClipInvocationCreateRequest`

NewBetaAppClipInvocationCreateRequest instantiates a new BetaAppClipInvocationCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBetaAppClipInvocationCreateRequestWithDefaults

`func NewBetaAppClipInvocationCreateRequestWithDefaults() *BetaAppClipInvocationCreateRequest`

NewBetaAppClipInvocationCreateRequestWithDefaults instantiates a new BetaAppClipInvocationCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *BetaAppClipInvocationCreateRequest) GetData() BetaAppClipInvocationCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *BetaAppClipInvocationCreateRequest) GetDataOk() (*BetaAppClipInvocationCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *BetaAppClipInvocationCreateRequest) SetData(v BetaAppClipInvocationCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *BetaAppClipInvocationCreateRequest) GetIncluded() []BetaAppClipInvocationLocalizationInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *BetaAppClipInvocationCreateRequest) GetIncludedOk() (*[]BetaAppClipInvocationLocalizationInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *BetaAppClipInvocationCreateRequest) SetIncluded(v []BetaAppClipInvocationLocalizationInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *BetaAppClipInvocationCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


