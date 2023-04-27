# AppCustomProductPageCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppCustomProductPageCreateRequestData**](AppCustomProductPageCreateRequestData.md) |  | 
**Included** | Pointer to [**[]AppCustomProductPageCreateRequestIncludedInner**](AppCustomProductPageCreateRequestIncludedInner.md) |  | [optional] 

## Methods

### NewAppCustomProductPageCreateRequest

`func NewAppCustomProductPageCreateRequest(data AppCustomProductPageCreateRequestData, ) *AppCustomProductPageCreateRequest`

NewAppCustomProductPageCreateRequest instantiates a new AppCustomProductPageCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageCreateRequestWithDefaults

`func NewAppCustomProductPageCreateRequestWithDefaults() *AppCustomProductPageCreateRequest`

NewAppCustomProductPageCreateRequestWithDefaults instantiates a new AppCustomProductPageCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppCustomProductPageCreateRequest) GetData() AppCustomProductPageCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppCustomProductPageCreateRequest) GetDataOk() (*AppCustomProductPageCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppCustomProductPageCreateRequest) SetData(v AppCustomProductPageCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppCustomProductPageCreateRequest) GetIncluded() []AppCustomProductPageCreateRequestIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppCustomProductPageCreateRequest) GetIncludedOk() (*[]AppCustomProductPageCreateRequestIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppCustomProductPageCreateRequest) SetIncluded(v []AppCustomProductPageCreateRequestIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppCustomProductPageCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


