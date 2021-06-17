<?php

namespace NSWDPC\Authentication\Okta;

use Http\Client\Curl\Client as CurlHttpClient;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Intercept the response and provide
 * @see https://github.com/okta/okta-sdk-php/issues/74
 * @see https://github.com/okta/okta-sdk-php/pull/105/commits/8289d88bdffb7ec7f21504e235eead8cfae64b86
 */
class ProxiedCurlHttpClient extends CurlHttpClient
{
    
    /**
     * @var ResponseInterface
     */
    protected $proxiedResponse = null;
    
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->proxiedResponse = null;
        $response = parent::sendRequest($request);
        $this->proxiedResponse = $response;
        return $response;
    }
    
    /**
     * Return the intercepted response
     */
    public function getLastResponse()
    {
        return $this->proxiedResponse;
    }
    
    /**
     * Get the Link header
     */
    public function getLinkHeader()
    {
        if ($this->getLastResponse()) {
            return $this->getLastResponse()->getHeader("Link");
        }
    }
    
    /**
     * Get the options to retrieve the next page of the collection
     * eg. Link: <https://${yourOktaDomain}/api/v1/users?after=00ubfjQEMYBLRUWIEDKK>; rel="next",
     * @return array query string options
     * @throws \Exception
     */
    public function getNextPageOptions() : array
    {
        $links = $this->getLinkHeader();
        if (empty($links) || !is_array($links)) {
            throw new \Exception("No Link header value returned containing multiple links");
        }
        
        // Return the header containing rel="next"
        $filterer = function ($v, $k) {
            $parts = explode(";", $v);
            return isset($parts[1]) && trim($parts[1]) == "rel=\"next\"";
        };
        $result = array_filter($links, $filterer, ARRAY_FILTER_USE_BOTH);
        
        // only one next value is allowed
        if (count($result) !== 1) {
            throw new \Exception("No results from array_filter");
        }
        
        // parse out the url parts
        $link = array_shift($result);
        $nextLink = substr($link, 1, strrpos($link, ">") -1);
        $parts = parse_url($nextLink);
        
        if (!empty($parts['query'])) {
            parse_str($parts["query"], $query);
            return $query;
        }
        
        throw new \Exception("No query string returned in next link");
    }
}
