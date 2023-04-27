# AppAvailabilityResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppAvailability**](AppAvailability.md) |  | 
**Included** | Pointer to [**[]AppAvailabilityResponseIncludedInner**](AppAvailabilityResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppAvailabilityResponse

`func NewAppAvailabilityResponse(data AppAvailability, links DocumentLinks, ) *AppAvailabilityResponse`

NewAppAvailabilityResponse instantiates a new AppAvailabilityResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppAvailabilityResponseWithDefaults

`func NewAppAvailabilityResponseWithDefaults() *AppAvailabilityResponse`

NewAppAvailabilityResponseWithDefaults instantiates a new AppAvailabilityResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppAvailabilityResponse) GetData() AppAvailability`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppAvailabilityResponse) GetDataOk() (*AppAvailability, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppAvailabilityResponse) SetData(v AppAvailability)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppAvailabilityResponse) GetIncluded() []AppAvailabilityResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppAvailabilityResponse) GetIncludedOk() (*[]AppAvailabilityResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppAvailabilityResponse) SetIncluded(v []AppAvailabilityResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppAvailabilityResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppAvailabilityResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppAvailabilityResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppAvailabilityResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


