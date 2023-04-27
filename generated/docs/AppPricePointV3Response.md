# AppPricePointV3Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppPricePointV3**](AppPricePointV3.md) |  | 
**Included** | Pointer to [**[]AppAvailabilityResponseIncludedInner**](AppAvailabilityResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppPricePointV3Response

`func NewAppPricePointV3Response(data AppPricePointV3, links DocumentLinks, ) *AppPricePointV3Response`

NewAppPricePointV3Response instantiates a new AppPricePointV3Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricePointV3ResponseWithDefaults

`func NewAppPricePointV3ResponseWithDefaults() *AppPricePointV3Response`

NewAppPricePointV3ResponseWithDefaults instantiates a new AppPricePointV3Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppPricePointV3Response) GetData() AppPricePointV3`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPricePointV3Response) GetDataOk() (*AppPricePointV3, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPricePointV3Response) SetData(v AppPricePointV3)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppPricePointV3Response) GetIncluded() []AppAvailabilityResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppPricePointV3Response) GetIncludedOk() (*[]AppAvailabilityResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppPricePointV3Response) SetIncluded(v []AppAvailabilityResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppPricePointV3Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppPricePointV3Response) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPricePointV3Response) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPricePointV3Response) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


