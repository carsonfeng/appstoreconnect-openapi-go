# AppClipDomainStatusAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Domains** | Pointer to [**[]AppClipDomainStatusAttributesDomainsInner**](AppClipDomainStatusAttributesDomainsInner.md) |  | [optional] 
**LastUpdatedDate** | Pointer to **time.Time** |  | [optional] 

## Methods

### NewAppClipDomainStatusAttributes

`func NewAppClipDomainStatusAttributes() *AppClipDomainStatusAttributes`

NewAppClipDomainStatusAttributes instantiates a new AppClipDomainStatusAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDomainStatusAttributesWithDefaults

`func NewAppClipDomainStatusAttributesWithDefaults() *AppClipDomainStatusAttributes`

NewAppClipDomainStatusAttributesWithDefaults instantiates a new AppClipDomainStatusAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetDomains

`func (o *AppClipDomainStatusAttributes) GetDomains() []AppClipDomainStatusAttributesDomainsInner`

GetDomains returns the Domains field if non-nil, zero value otherwise.

### GetDomainsOk

`func (o *AppClipDomainStatusAttributes) GetDomainsOk() (*[]AppClipDomainStatusAttributesDomainsInner, bool)`

GetDomainsOk returns a tuple with the Domains field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDomains

`func (o *AppClipDomainStatusAttributes) SetDomains(v []AppClipDomainStatusAttributesDomainsInner)`

SetDomains sets Domains field to given value.

### HasDomains

`func (o *AppClipDomainStatusAttributes) HasDomains() bool`

HasDomains returns a boolean if a field has been set.

### GetLastUpdatedDate

`func (o *AppClipDomainStatusAttributes) GetLastUpdatedDate() time.Time`

GetLastUpdatedDate returns the LastUpdatedDate field if non-nil, zero value otherwise.

### GetLastUpdatedDateOk

`func (o *AppClipDomainStatusAttributes) GetLastUpdatedDateOk() (*time.Time, bool)`

GetLastUpdatedDateOk returns a tuple with the LastUpdatedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastUpdatedDate

`func (o *AppClipDomainStatusAttributes) SetLastUpdatedDate(v time.Time)`

SetLastUpdatedDate sets LastUpdatedDate field to given value.

### HasLastUpdatedDate

`func (o *AppClipDomainStatusAttributes) HasLastUpdatedDate() bool`

HasLastUpdatedDate returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


